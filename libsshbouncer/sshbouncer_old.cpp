
#include "bpf/sshtrace_events.h"
#include "existing_connections.h"
#include "pts_parser.h"
#include "sshtrace.skel.h"
#include "tclap/CmdLine.h"
#include <argp.h>
#include <arpa/inet.h>
#include <iostream>
#include <iterator>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

using namespace sshbouncer;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  bool verbose = false;
  if (level == LIBBPF_DEBUG && !verbose)
    return 0;
  return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

static void handle_event(void *ctx, int cpu, void *data, uint32_t data_sz) {
  const struct event *e_generic = (const struct event *)data;
  struct sshtrace_bpf *skel = (struct sshtrace_bpf *)ctx;

  int event_type = e_generic->event_type;

  printf("EVENT! %d\n", event_type);
  if (event_type == SSHTRACE_EVENT_BASH_CLONED) {
    const struct bash_clone_event *e = (const struct bash_clone_event *)data;
    printf("BASH EVENT! %d bash %d pts %d ptm %d\n", event_type, e->bash_pid,
           e->pts_pid, e->ptm_pid);

    PtsParser pts_parser(e->pts_pid);

    if (pts_parser.pts_fd_1 != PTS_UNKNOWN) {
      // int connections_fd = bpf_map__fd(skel->maps.connections);
      struct connection conn;
      int success =
          bpf_map__lookup_elem(skel->maps.connections, &e->ptm_pid,
                               sizeof(e->ptm_pid), &conn, sizeof(conn), 0);
      printf("CONN: success %d\n", success);
      if (success != 0) {
        printf("Error, cannot find connection for pid %d\n", e->ptm_pid);
      } else {
        conn.pts_fd = pts_parser.pts_fd_1;
        conn.pts_fd2 = pts_parser.pts_fd_2;
        conn.pts_fd3 = pts_parser.pts_fd_3;
        conn.user_id = pts_parser.user_id;
        conn.shell_tgid = e->bash_pid;
        bpf_map__update_elem(skel->maps.connections, &e->ptm_pid,
                             sizeof(e->ptm_pid), &conn, sizeof(conn),
                             BPF_EXIST);
      }
    }
  } else if (event_type == SSHTRACE_TERMINAL_UPDATE) {

    const struct terminal_update_event *e =
        (const struct terminal_update_event *)data;

    printf("pid %d: %s\n", e->ptm_pid, e->terminal_data);
  } else if (event_type == SSHTRACE_EVENT_NEW_CONNECTION) {
    const struct connection_event *e = (const struct connection_event *)data;

    struct in_addr ip_addr;
    ip_addr.s_addr = e->conn.tcp_info.client_ip;
    char *ip_str = inet_ntoa(ip_addr);

    printf("new connection pid %d: user %d from address %s:%d\n", e->ptm_pid,
           e->conn.user_id, ip_str, e->conn.tcp_info.client_port);
  } else if (event_type == SSHTRACE_EVENT_CLOSE_CONNECTION) {

    const struct connection_event *e = (const struct connection_event *)data;
    struct in_addr ip_addr;
    ip_addr.s_addr = e->conn.tcp_info.client_ip;
    char *ip_str = inet_ntoa(ip_addr);
    printf("Close connection pid %d: user %d from address %s:%d\n", e->ptm_pid,
           e->conn.user_id, ip_str, e->conn.tcp_info.client_port);
  } else if (event_type == SSHTRACE_EVENT_COMMAND_START) {

    const struct command_event *e = (const struct command_event *)data;
    printf("Command start: %s\n", e->cmd.args);

  } else if (event_type == SSHTRACE_EVENT_COMMAND_END) {

    const struct command_event *e = (const struct command_event *)data;
    printf("Command end: %d %s\n", e->cmd.stdout_offset, e->cmd.stdout);
  }

  printf("Event handled %d\n", event_type);
}
static void handle_perf_dropped(void *ctx, int cpu, __u64 cnt) {
  printf("DROPPED DATA\n");
}

static struct connection
create_connection(struct ssh_session existing_session) {
  struct connection c;
  c.pts_tgid = existing_session.pts_pid;
  c.ptm_tgid = existing_session.ptm_pid;
  c.shell_tgid = existing_session.bash_pid;
  c.start_time = existing_session.start_time;
  c.user_id = existing_session.user_id;

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

  return c;
}

int main(int argc, const char **argv) {

  bool debug_mode = false;

  TCLAP::CmdLine cmd("SSHBouncer Command Line Utility", ' ', "1.0.0");

  TCLAP::SwitchArg debugSwitch("", "debug", "Enable debug output.  Default=off",
                               cmd, false);

  try {
    // cmd.add(somethingArg);

    cmd.parse(argc, argv);

    debug_mode = debugSwitch.getValue();

  } catch (TCLAP::ArgException &e) {
    std::cerr << "error: " << e.error() << " for arg " << e.argId()
              << std::endl;
    return 1;
  }

  // First, identify all existing SSH connections and insert them.
  // The BPF hooks will only identify new connections moving forward
  ExistingConnections existing_conns;

  // Figure ~200KB of event buffer.  Must be a power of 2.  Each memory page
  // is ~4096 bytes
  const int PERF_BUFFER_NUM_MEMORY_PAGES = 64;

  struct perf_buffer *pb = NULL;
  // struct ring_buffer *rb = NULL;
  struct sshtrace_bpf *skel;
  int err;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Load and verify BPF application */
  skel = sshtrace_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  /* Parameterize BPF code with minimum duration parameter */
  // skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

  /* Load & verify BPF programs */
  err = sshtrace_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoints */
  err = sshtrace_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  // Insert existing connections for tracking
  for (auto &existing_session : existing_conns.get_sessions()) {
    struct connection conn = create_connection(existing_session);
    bpf_map__update_elem(skel->maps.connections, &conn.ptm_tgid,
                         sizeof(conn.ptm_tgid), &conn, sizeof(conn), BPF_ANY);
  }

  /* Set up perf buffer polling */

  pb = perf_buffer__new(bpf_map__fd(skel->maps.events),
                        PERF_BUFFER_NUM_MEMORY_PAGES, handle_event,
                        handle_perf_dropped, skel, NULL);
  if (!pb) {
    err = -1;
    fprintf(stderr, "Failed to create perf buffer\n");
    goto cleanup;
  }

  /* Process events */
  printf("%-8s %-5s %-16s %-7s %-7s %s\n", "TIME", "EVENT", "COMM", "PID",
         "PPID", "FILENAME/EXIT CODE");
  while (!exiting) {
    err = perf_buffer__poll(pb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  /* Clean up */
  perf_buffer__free(pb);
  sshtrace_bpf__destroy(skel);

  return err < 0 ? -err : 0;

  return 0;
}
