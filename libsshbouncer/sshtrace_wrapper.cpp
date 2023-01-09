#include "sshtrace_wrapper.h"
#include "bpf/sshtrace_events.h"
#include "event_serializer.h"
#include "existing_connections.h"
#include "pts_parser.h"
#include <argp.h>
#include <arpa/inet.h>
#include <iostream>
#include <iterator>
#include <plog/Log.h>
#include <pwd.h>
#include <sstream>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

namespace sshbouncer {

// local prototypes
static struct connection create_connection(struct ssh_session existing_session);
#ifdef SSHTRACE_USE_RINGBUF
static int handle_event(void* ctx, void* data, size_t data_sz);
#else
static void handle_event(void* ctx, int cpu, void* data, uint32_t data_sz);
#endif
static void handle_perf_dropped(void* ctx, int cpu, __u64 cnt);
static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args);

static bool exited = false;
static void bpf_poll_loop(SSHTraceWrapper* ctx) {
  while (!exited && ctx->is_ok()) {
#ifdef SSHTRACE_USE_RINGBUF
    ctx->bpf_err_code = ring_buffer__poll(ctx->pb, 50 /* timeout, ms */);
#else
    ctx->bpf_err_code = perf_buffer__poll(ctx->pb, 50 /* timeout, ms */);
#endif
    if (ctx->bpf_err_code == -EINTR) {
      // Caused by CTRL+C -- no need to report error
      break;
    } else if (ctx->bpf_err_code < 0) {
      PLOG_WARNING << "Error polling perf buffer: " << ctx->bpf_err_code;
      break;
    }
  }
  if (exited)
    PLOG_INFO << "Exiting BPF polling";
  else
    PLOG_WARNING << "Exiting BPF polling due to error code " << ctx->bpf_err_code;
}

SSHTraceWrapper::SSHTraceWrapper() {

  // First, identify all existing SSH connections and insert them.
  // The BPF hooks will only identify new connections moving forward
  ExistingConnections existing_conns;

  // Figure ~4MB of event buffer.  Must be a power of 2.  Each memory page
  // is ~4096 bytes
  const int PERF_BUFFER_NUM_MEMORY_PAGES = 1024;

  bpf_err_code = 0;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Load and verify BPF application */
  skel = sshtrace_bpf__open();
  if (!skel) {
    PLOG_FATAL << "Failed to open and load BPF skeleton";
    bpf_err_code = -1;
    return;
  }

  /* Parameterize BPF code with minimum duration parameter */
  // skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

  /* Load & verify BPF programs */
  bpf_err_code = sshtrace_bpf__load(skel);
  if (bpf_err_code) {
    PLOG_FATAL << "Failed to load and verify BPF skeleton";
    return;
  }

  /* Attach tracepoints */
  bpf_err_code = sshtrace_bpf__attach(skel);
  if (bpf_err_code) {
    PLOG_FATAL << "Failed to attach BPF skeleton";
    return;
  }

  // Insert existing connections for tracking
  for (auto& existing_session : existing_conns.get_sessions()) {
    struct connection conn = create_connection(existing_session);
    bpf_map__update_elem(skel->maps.connections, &conn.ptm_tgid, sizeof(conn.ptm_tgid), &conn, sizeof(conn), BPF_ANY);

    // Add all existing connections directly to the event queue
    struct connection_event e;
    e.conn = conn;
    e.event_type = SSHTRACE_EVENT_NEW_CONNECTION;
    e.ptm_pid = conn.ptm_tgid;
    char* json_data = serialize_event(&e);
    q.enqueue(json_data);
  }

  /* Set up perf buffer polling */

#ifdef SSHTRACE_USE_RINGBUF
  pb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, this, NULL);
#else
  pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_NUM_MEMORY_PAGES, handle_event, handle_perf_dropped,
                        this, NULL);
#endif
  if (!pb) {
    bpf_err_code = -1;
    PLOG_FATAL << "Failed to create perf buffer";
    return;
  }

  bpf_poll_thread = std::make_unique<std::thread>(bpf_poll_loop, this);
}

SSHTraceWrapper::~SSHTraceWrapper() {
  /* Clean up */
  exited = true;
  if (bpf_poll_thread->joinable())
    bpf_poll_thread->join();

#ifdef SSHTRACE_USE_RINGBUF
  ring_buffer__free(pb);
#else
  perf_buffer__free(pb);
#endif
  sshtrace_bpf__destroy(skel);
}

char* SSHTraceWrapper::poll(int timeout_ms) {

  const int MICROSEC_IN_A_MILLISEC = 1000;
  char* obj;
  bool success = q.wait_dequeue_timed(obj, timeout_ms * MICROSEC_IN_A_MILLISEC);

  if (!success) {
    PLOG_VERBOSE << "Polling for data...";
    return nullptr;
  }

  return obj;
  // char *themem = (char *)malloc(100);
  // return themem;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  bool verbose = false;
  if (level == LIBBPF_DEBUG && !verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

static std::string getUser(uid_t uid) {
  struct passwd* pws;
  pws = getpwuid(uid);
  return pws->pw_name;
}
#ifdef SSHTRACE_USE_RINGBUF
static int handle_event(void* ctx, void* data, size_t data_sz) {
#else
static void handle_event(void* ctx, int cpu, void* data, uint32_t data_sz) {
#endif
  const struct event* e_generic = (const struct event*) data;
  SSHTraceWrapper* wrapper = (SSHTraceWrapper*) ctx;

  struct sshtrace_bpf* skel = wrapper->skel;

  int event_type = e_generic->event_type;

  PLOG_DEBUG << "Event type " << event_type;

  switch (event_type) {
  case SSHTRACE_EVENT_NEW_CONNECTION:
  case SSHTRACE_EVENT_CLOSE_CONNECTION:
  case SSHTRACE_EVENT_COMMAND_START:
  case SSHTRACE_EVENT_COMMAND_END:
  case SSHTRACE_EVENT_TERMINAL_UPDATE: {
    char* json_data = serialize_event(data);
    PLOG_VERBOSE << json_data;
    wrapper->q.enqueue(json_data);
    break;
  }
  default:
    break;
  }

  if (event_type == SSHTRACE_EVENT_BASH_CLONED) {
    const struct bash_clone_event* e = (const struct bash_clone_event*) data;
    PLOG_DEBUG << "Bash clone event.  Bash PID: " << e->bash_pid << " PTS PID: " << e->pts_pid
               << " PTM PID: " << e->ptm_pid;

    PtsParser pts_parser(e->pts_pid);

    if (pts_parser.pts_fd_1 != PTS_UNKNOWN) {
      // int connections_fd = bpf_map__fd(skel->maps.connections);
      struct connection conn;
      int success =
          bpf_map__lookup_elem(skel->maps.connections, &e->ptm_pid, sizeof(e->ptm_pid), &conn, sizeof(conn), 0);

      if (success != 0) {
        PLOG_WARNING << "Cannot find connection info for ptm PID " << e->ptm_pid;
      } else {
        conn.pts_fd = pts_parser.pts_fd_1;
        conn.pts_fd2 = pts_parser.pts_fd_2;
        conn.pts_fd3 = pts_parser.pts_fd_3;
        conn.user_id = pts_parser.user_id;
        strcpy(conn.username, getUser(conn.user_id).c_str());
        conn.tty_id = pts_parser.tty_id;
        conn.shell_tgid = e->bash_pid;
        bpf_map__update_elem(skel->maps.connections, &e->ptm_pid, sizeof(e->ptm_pid), &conn, sizeof(conn), BPF_EXIST);
      }
    } else {
      PLOG_WARNING << "Cannot parse FD/TTY data for ptm PID " << e->ptm_pid;
    }
  }

  // Only parse/run this code for debug output
  IF_PLOG(plog::debug) {
    if (event_type == SSHTRACE_EVENT_TERMINAL_UPDATE) {

      const struct terminal_update_event* e = (const struct terminal_update_event*) data;

      PLOG_VERBOSE << "terminal update: pid " << e->ptm_pid << e->terminal_data;
    } else if (event_type == SSHTRACE_EVENT_NEW_CONNECTION) {
      const struct connection_event* e = (const struct connection_event*) data;

      struct in_addr ip_addr;
      ip_addr.s_addr = e->conn.tcp_info.client_ip;
      char* ip_str = inet_ntoa(ip_addr);

      PLOG_DEBUG << "new connection: pid " << e->ptm_pid << " user: " << e->conn.username << " address: " << ip_str
                 << ":" << e->conn.tcp_info.client_port;

    } else if (event_type == SSHTRACE_EVENT_CLOSE_CONNECTION) {

      const struct connection_event* e = (const struct connection_event*) data;
      struct in_addr ip_addr;
      ip_addr.s_addr = e->conn.tcp_info.client_ip;
      char* ip_str = inet_ntoa(ip_addr);

      PLOG_DEBUG << "close connection: pid " << e->ptm_pid << " user: " << e->conn.username << " address: " << ip_str
                 << ":" << e->conn.tcp_info.client_port;

    } else if (event_type == SSHTRACE_EVENT_COMMAND_START) {

      const struct command_event* e = (const struct command_event*) data;
      PLOG_DEBUG << "command start: " << e->cmd.args;

    } else if (event_type == SSHTRACE_EVENT_COMMAND_END) {

      const struct command_event* e = (const struct command_event*) data;
      PLOG_DEBUG << "command end: " << e->cmd.args << " " << e->cmd.stdout;
    }
  }

#ifdef SSHTRACE_USE_RINGBUF
  return 0;
#endif
}
static void handle_perf_dropped(void* ctx, int cpu, __u64 cnt) {
  PLOG_WARNING << "Dropping data due to overloaded perf buffer";
}

static struct connection create_connection(struct ssh_session existing_session) {
  struct connection c;
  c.pts_tgid = existing_session.pts_pid;
  c.ptm_tgid = existing_session.ptm_pid;
  c.shell_tgid = existing_session.bash_pid;
  c.start_time = existing_session.start_time;
  c.user_id = existing_session.user_id;
  strcpy(c.username, getUser(c.user_id).c_str());

  // Convert IP address back out to integer
  struct sockaddr_in sa;
  inet_pton(AF_INET, existing_session.client_ip.c_str(), &(sa.sin_addr));
  c.tcp_info.client_ip = sa.sin_addr.s_addr;
  c.tcp_info.client_port = existing_session.client_port;

  inet_pton(AF_INET, existing_session.server_ip.c_str(), &(sa.sin_addr));
  c.tcp_info.server_ip = sa.sin_addr.s_addr;
  c.tcp_info.server_port = existing_session.server_port;

  PtsParser pts_info(existing_session.pts_pid);
  c.pts_fd = pts_info.pts_fd_1;
  c.pts_fd2 = pts_info.pts_fd_2;
  c.pts_fd3 = pts_info.pts_fd_3;
  c.tty_id = pts_info.tty_id;

  return c;
}

} // namespace sshbouncer