/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2023- Open Kilt LLC.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include "sshtrace_events.h"
#include "sshtrace_heap.h"
#include "sshtrace_types.h"
#include "vmlinux/vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// PROC hierarchy (101-> are created for each session):
// PID    PARENT PID      Proc
// 100      1              sshd
// 101      100            pt master
// 102      101            pt slave
// 103      102            sh/bash or whatever

// Swap these defines out for debugging.  Logs can be seen with:
// sudo cat /sys/kernel/debug/tracing/trace_pipe
#ifdef SSHTRACE_DEBUG
#define log_printk(fmt, args...) bpf_printk(fmt, ##args)
#else
#define log_printk(fmt, args...)
#endif

#ifdef SSHTRACE_USE_RINGBUF
// Ringbuf is more efficient but requires at least kernel version 5.8
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096 * 1024 /* 4 MB */);
} events SEC(".maps");
#else

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");
#endif

struct socket_map {
  struct sockaddr* addr;
  struct tcpinfo recent_tcpinfo;
};

// Just used to temporarily map a pointer between enter_accept and exit_accept
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 100);
  __type(key, u32);
  __type(value, struct socket_map);
} socket_mapping SEC(".maps");

// Provide a sane limit on buffer size for tracking concurrently running programs (hash size)
// memory usage = MAX_CONCURRENT_PROGRAMS * (STDOUT_ACTUAL_MEM_USAGE_BYTES + sizeof(command2) + COMMAND_ARGS_ACTUAL_MEM_USAGE_BYTES)
// so for 2000, about ~20MB
#define MAX_CONCURRENT_PROGRAMS 2000

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_CONCURRENT_PROGRAMS);
  __type(key, u32);
  __type(value, struct command);
} commands SEC(".maps");

#define MAX_CONNECTIONS 10000
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_CONNECTIONS);
  __type(key, u32);
  __type(value, struct connection);
} connections SEC(".maps");

// Maps the data pointer between read enter and read exit
struct read_buffer_map {
  int fd;
  void* data_ptr;
};
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, MAX_CONNECTIONS);
  __type(key, u32);
  __type(value, struct read_buffer_map);
} connections_read_mapping SEC(".maps");

// Local constants since we can't include std headers
static const int AF_UNIX = 1;
static const int AF_INET = 2;
static const int AF_INET6 = 10; // TODO: Test and add support for ipv6

static const int STDIN_FILENO = 0;
static const int STDOUT_FILENO = 1;
static const int STDERR_FILENO = 2;

static void push_event(void* context, void* event, size_t event_size) {

#ifdef SSHTRACE_USE_RINGBUF
  // TODO consider more efficient bpf_ringbuf_reserve()/bpf_ringbuf_commit()
  int64_t success = bpf_ringbuf_output(&events, event, event_size, 0);
  if (success < 0)
    log_printk("event push error code: %d", success);

#else
  bpf_perf_event_output(context, &events, BPF_F_CURRENT_CPU, event, event_size);
#endif
}
static int proc_is_sshd(void) {
  // Just needs to be bigger than sshd\0
  char comm[6];

  bpf_get_current_comm(&comm, sizeof(comm));

  // Check that process name is "sshd"
  if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd' && comm[4] == '\0')
    return 1;
  return 0;
}

static u64 get_parent_pid(void) {
  struct task_struct* curr = (struct task_struct*) bpf_get_current_task();
  struct task_struct* parent = (struct task_struct*) BPF_CORE_READ(curr, parent);

  if (parent == NULL)
    return 0;

  u32 p_tgid = BPF_CORE_READ(parent, tgid);
  u32 p_pid = BPF_CORE_READ(parent, pid);
  return ((u64) p_tgid << 32) | p_pid;
}

static u64 get_grandparent_pid(void) {
  struct task_struct* curr = (struct task_struct*) bpf_get_current_task();
  struct task_struct* parent = (struct task_struct*) BPF_CORE_READ(curr, parent);
  struct task_struct* gparent = (struct task_struct*) BPF_CORE_READ(parent, parent);

  if (parent == NULL)
    return 0;

  u32 p_tgid = BPF_CORE_READ(gparent, tgid);
  u32 p_pid = BPF_CORE_READ(gparent, pid);

  return ((u64) p_tgid << 32) | p_pid;
}

static struct connection* find_ancestor_connection(void) {
  struct task_struct* tsk = (struct task_struct*) bpf_get_current_task();
  struct connection* conn;

  //log_printk("ancestor search start");

  // put a max cap on looping back to parent
  for (int i = 0; i < 20; i++) {
    u32 tgid = BPF_CORE_READ(tsk, tgid);
    if (tgid <= 1) {
      //log_printk("Reached root tgid %u\n", tgid);
      break;
    }

    //log_printk("my tgid %u\n", tgid);

    conn = bpf_map_lookup_elem(&connections, &tgid);
    if (conn != NULL)
      return conn;
    tsk = (struct task_struct*) BPF_CORE_READ(tsk, parent);
  }

  return NULL;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int sys_enter_accept(struct trace_event_raw_sys_enter* ctx) {
  // field:int fd;	offset:16;	size:8;	signed:0;
  // field:struct sockaddr * upeer_sockaddr;	offset:24;	size:8;	signed:0;
  // field:int * upeer_addrlen;	offset:32;	size:8;	signed:0;

  if (!proc_is_sshd())
    return 1;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  struct socket_map sockmap = {0};
  sockmap.recent_tcpinfo.client_ip = 0;
  sockmap.recent_tcpinfo.server_ip = 0;
  sockmap.recent_tcpinfo.client_port = 0;
  sockmap.recent_tcpinfo.server_port = 0;

  uint32_t socket_id = (uint32_t) BPF_CORE_READ(ctx, args[0]);
  sockmap.addr = (struct sockaddr*) BPF_CORE_READ(ctx, args[1]);
  //int* addrlen = (int*) BPF_CORE_READ(ctx, args[2]);

  bpf_map_update_elem(&socket_mapping, &pid_tgid, &sockmap, BPF_ANY);

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int sys_exit_accept(struct trace_event_raw_sys_exit* ctx) {
  if (!proc_is_sshd())
    return 1;

  u64 pid_tgid = bpf_get_current_pid_tgid();

  int32_t ret = (int32_t) BPF_CORE_READ(ctx, ret);

  struct socket_map* sockmap = bpf_map_lookup_elem(&socket_mapping, &pid_tgid);

  // 1. Check if map lookup succeeded
  if (sockmap == NULL)
    return 1;

  // 2. Now it is safe to read sockmap->addr
  struct sockaddr* addr_peer = sockmap->addr;

  // 3. Check if the internal pointer is valid
  if (addr_peer == NULL)
    return 1;

  u32 sock_family = BPF_CORE_READ_USER(addr_peer, sa_family);

  if (sock_family == AF_INET) {
    struct sockaddr_in* inet_socket = (struct sockaddr_in*) addr_peer;

    u16 port = BPF_CORE_READ_USER(inet_socket, sin_port); // & 0xffff;
    port = __builtin_bswap16(port);

    u32 ip_address = BPF_CORE_READ_USER(inet_socket, sin_addr.s_addr);
    //ip_address = __builtin_bswap32(ip_address);

    sockmap->recent_tcpinfo.client_ip = ip_address;
    sockmap->recent_tcpinfo.server_ip = 0; // Unknown
    sockmap->recent_tcpinfo.client_port = port;
    sockmap->recent_tcpinfo.server_port = 0; // Unknown

  } else if (sock_family == AF_INET6) {
    // TODO: support IPv6
    // struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
    // port = ntohs(s->sin6_port);
    // inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
  }

  log_printk("sys_exit_accept tgid: %d fd: %d", pid_tgid, ret);

  return 0;
}

// TODO: This also works, and provides more information (server port and IP address)
// But I do not like that it is less maintainable (i.e., it's a kernel probe instead of tracepoint)
// SEC("kretprobe/inet_csk_accept")
// int BPF_KRETPROBE(inet_csk_accept_ret, struct sock *newsk)
// {

// 	if (!proc_is_sshd())
// 		return 1;

// 	if (newsk == NULL)
// 		return 0;

// 	u64 pid_tgid = bpf_get_current_pid_tgid();
// 	struct sshd_listener *listener;

// 	if ((listener = get_sshd_listener()) == NULL)
// 		return 1;

// 	u16 family = 0;
// 	bpf_core_read(&family, sizeof(family), &newsk->__sk_common.skc_family);

// 	if (family == AF_INET)
// 	{

// 		u16 client_port = 0, server_port = 0;
// 		u32 client_ip = 0, server_ip = 0;
// 		bpf_core_read(&client_port, sizeof(client_port), &newsk->__sk_common.skc_dport);
// 		bpf_core_read(&server_port, sizeof(server_port), &newsk->__sk_common.skc_num);
// 		bpf_core_read(&client_ip, sizeof(client_ip), &newsk->__sk_common.skc_daddr);
// 		bpf_core_read(&server_ip, sizeof(server_ip), &newsk->__sk_common.skc_rcv_saddr);

// 		client_port = __builtin_bswap16(client_port);
// 		client_ip = __builtin_bswap32(client_ip);
// 		server_ip = __builtin_bswap32(server_ip);

// 		// TODO, is there a race condition here?
// 		// e.g., two SSH sessions happen around the same time and the connections get crossed...
// 		// If so, recent_tcpinfo needs to be a global hash with some unique ID to differentiate.
// 		listener->pid_tgid = pid_tgid;
// 		listener->recent_tcpinfo.client_ip = client_ip;
// 		listener->recent_tcpinfo.server_ip = server_ip;
// 		listener->recent_tcpinfo.client_port = client_port;
// 		listener->recent_tcpinfo.server_port = server_port;

// 		log_printk("inet_csk_accept fd: %d %d %u", pid_tgid, client_port, server_port);
// 	}

// 	return 0;

// }

static bool is_ptm_clone(u64 pid_tgid) {
  struct socket_map* sockmap = bpf_map_lookup_elem(&socket_mapping, &pid_tgid);

  if (sockmap == NULL)
    return false;

  return true;
}

static void handle_new_connection(void* context, u32 sshd_tgid, u32 conn_tgid) {

  struct socket_map* sockmap = bpf_map_lookup_elem(&socket_mapping, &sshd_tgid);
  struct connection conn = {};

  log_printk("conn_tgid  %d parent %d\n", conn_tgid, sshd_tgid);
  if (sockmap == NULL)
    return;

  conn.ptm_tgid = conn_tgid;
  conn.user_id = -1;
  conn.pts_tgid = -1;
  conn.shell_tgid = -1;
  conn.tty_id = -1;
  conn.tcp_info = sockmap->recent_tcpinfo;

  conn.start_time = bpf_ktime_get_ns();
  conn.end_time = 0;
  conn.rate_limit_epoch_second = 0;
  conn.rate_limit_hit = false;
  conn.rate_limit_total_bytes_this_second = 0;

  // cleanup sockmap
  bpf_map_delete_elem(&socket_mapping, &sshd_tgid);

  bpf_map_update_elem(&connections, &conn_tgid, &conn, BPF_ANY);

  // The PTM has been created now, go ahead and send the event
  int zero = 0;
  struct connection_event* e = bpf_map_lookup_elem(&connectionevent_heap, &zero);
  if (!e)
    return;

  e->event_type = SSHTRACE_EVENT_NEW_CONNECTION;
  e->ptm_pid = conn.ptm_tgid;
  e->conn = conn;
  push_event(context, e, sizeof(struct connection_event));

  log_printk("conn ptm_tgid %u\n", conn_tgid);
}

static bool is_pts_clone(u32 tgid) {
  struct connection* conn;

  conn = bpf_map_lookup_elem(&connections, &tgid);
  if (conn == NULL)
    return false;

  return tgid == conn->ptm_tgid;
}

static bool is_bash_clone() {
  u32 parent_tgid = get_parent_pid() >> 32;

  struct connection* conn = bpf_map_lookup_elem(&connections, &parent_tgid);
  if (conn == NULL)
    return false;

  return true;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int sys_exit_clone(struct trace_event_raw_sys_exit* ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();

  // mhill add
  if (!proc_is_sshd())
    return 1;

  log_printk("sys_exit_clone\n");

  int32_t ret = (int32_t) BPF_CORE_READ(ctx, ret);

  u32 child_tgid = ret;

  if (is_pts_clone(pid_tgid >> 32)) {
    log_printk("CLONE CONNECTION parent pid %d child pid %d", pid_tgid, child_tgid);

    struct connection* conn = bpf_map_lookup_elem(&connections, &pid_tgid);

    if (conn != NULL) {

      conn->pts_tgid = child_tgid;
    }

    return 0;
  }

  if (is_ptm_clone(pid_tgid)) {
    log_printk("NEW CONNECTION parent pid %d child pid %d", pid_tgid, child_tgid);
    handle_new_connection(ctx, pid_tgid, child_tgid);

    return 0;
  }

  if (is_bash_clone() && child_tgid != 0) {

    log_printk("NEW BASH CONNECTION parent pid %d child pid %d", pid_tgid, child_tgid);

    // The FD mapping for PTS is too squirrelly.  Instead of chasing the ioctl -> dup calls
    // (which could change between openssh versions) a more reliable method seems to be,
    // Wait for the pts proc to fork a terminal, and when it does, pop a message out to user-space to
    // go lookup the FDs for the pts sessions in /proc/[pid]/fd/.  Then update the map back here
    // It's possible we miss a little bit of initial terminal reads due to the poll interval

    // We'll need to have this logic in userspace anyway, for when our proc is started while
    // sessions already exist monitor existing sessions

    struct bash_clone_event e;
    e.event_type = SSHTRACE_EVENT_BASH_CLONED;
    e.pts_pid = pid_tgid;
    e.bash_pid = child_tgid;
    e.ptm_pid = get_parent_pid() >> 32;

    push_event(ctx, &e, sizeof(e));
  }

  return 0;
}

#define O_WRONLY 01
SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct trace_event_raw_sys_enter* ctx) {

  // field:int dfd;  offset:16;      size:8; signed:0;
  // field:const char * filename;    offset:24;      size:8; signed:0;
  // field:int flags;        offset:32;      size:8; signed:0;
  // field:umode_t mode;     offset:40;      size:8; signed:0;

  // Just needs to be bigger than scp\0
  char pname[5];

  bpf_get_current_comm(&pname, sizeof(pname));

  // Check that process name is "scp"
  if (pname[0] != 's' || pname[1] != 'c' || pname[2] != 'p' || pname[3] != '\0') {
    return 0;
  }

  // This needs to be a direct descendent of PTS (i.e., no bash or shell in between)
  // Otherwise, this is not an scp upload
  u32 gparent_tgid = get_grandparent_pid() >> 32;
  struct connection* conn = bpf_map_lookup_elem(&connections, &gparent_tgid);
  if (conn != NULL) {

    u32 flags = (size_t) BPF_CORE_READ(ctx, args[2]);

    if (flags & O_WRONLY) {
      u32 mode = (size_t) BPF_CORE_READ(ctx, args[3]);

      int zero = 0;
      struct file_upload_event* e = bpf_map_lookup_elem(&fileuploadevent_heap, &zero);
      if (!e)
        return 0;

      e->event_type = SSHTRACE_EVENT_FILE_UPLOAD;
      e->ptm_pid = conn->ptm_tgid;
      e->file_mode = mode;

      const char* filename_ptr = (const char*) BPF_CORE_READ(ctx, args[1]);
      //static char filename[255];
      bpf_core_read_user_str(e->target_path, sizeof(e->target_path), ctx->args[1]);

      u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
      log_printk("scp open event: pid: %d ptm_pid %d - %s", current_tgid, e->ptm_pid, e->target_path);

      push_event(ctx, e, sizeof(struct file_upload_event));

      // u32 dfd = (size_t) BPF_CORE_READ(ctx, args[0]);
      // log_printk("open:  tgid: %d - %s",  current_tgid, filename);)
      // log_printk("open:  dfd: %d flags: %d mode: %d",  dfd, flags, mode;
    }
  }

  return 0;
}

static int sys_enter_exec_common(struct trace_event_raw_sys_enter* ctx) {
  // field:const char * filename;	offset:16;	size:8;	signed:0;
  // field:const char *const * argv;	offset:24;	size:8;	signed:0;
  // field:const char *const * envp;	offset:32;	size:8;	signed:0;

  u32 parent_tgid = get_parent_pid() >> 32;
  u32 current_tgid = bpf_get_current_pid_tgid() >> 32;

  const char* filename = (const char*) BPF_CORE_READ(ctx, args[0]);
  const char* const* argv = (const char* const*) BPF_CORE_READ(ctx, args[1]);
  const char* const* envp = (const char* const*) BPF_CORE_READ(ctx, args[2]);

  // FOR TROUBLESHOOTING
  // static char fn[255] = {0};
  // bpf_core_read_user_str(fn, sizeof(fn), filename);
  // log_printk("sys_enter_execve: parent_tgid: %d, current_tgid: %d - %s", parent_tgid, current_tgid, fn);

  struct connection* conn;

  int zero = 0;
  struct command* cmd = bpf_map_lookup_elem(&command_heap, &zero);
  if (!cmd)
    return 0;

  if ((conn = find_ancestor_connection()) == NULL)
    return 1;

  cmd->filename[0] = '\0';
  cmd->start_time = bpf_ktime_get_ns();
  cmd->end_time = 0;
  cmd->exit_code = -1;
  cmd->parent_tgid = parent_tgid;
  cmd->current_tgid = current_tgid;
  cmd->stdout_offset = 0;
  cmd->conn_tgid = conn->ptm_tgid;
  cmd->stdout[0] = '\0';
  cmd->args[0] = '\0';

  // Copy the "Command" from args[0] rather than filename
  // because filename without path is bounded at 255 bytes

  char* arg0_ptr = NULL;
  bpf_core_read_user(&arg0_ptr, sizeof(arg0_ptr), argv);
  bpf_core_read_user_str(cmd->filename, sizeof(cmd->filename), arg0_ptr);

  log_printk("sys_enter_execve: conn tgid: %d, tgid: %d - %s", conn->ptm_tgid, current_tgid, cmd->filename);

  //bpf_core_read_str(cmd.filename, sizeof(cmd.filename), args->filename);

  // Read full filename and args data into map
  u32 argoffset = 0;

  // Copy the filename first, this is the full path not just the filename from args
  int bytes_read = argoffset = bpf_core_read_user_str(cmd->args, COMMAND_ARGS_MAX_BYTES, filename);
  log_printk("args copied bytes %d - %s", bytes_read, filename);
  argoffset = argoffset & COMMAND_ARGS_MAX_BYTES - 1;
  cmd->args[(argoffset - 1) & COMMAND_ARGS_MAX_BYTES - 1] = ' ';

  for (u32 i = 1; i < sizeof(argv); i++) {
    char* argv_p = NULL;
    bpf_core_read_user(&argv_p, sizeof(argv_p), argv + i);

    if (!argv_p)
      break;

    bytes_read = bpf_core_read_user_str(cmd->args + argoffset, COMMAND_ARGS_MAX_BYTES - argoffset, argv_p);
    //int bytes_read = bpf_core_read_user_str(cmd.args, COMMAND_ARGS_MAX_BYTES , argv_p);
    log_printk("args copied bytes %d - %s", bytes_read, argv_p);

    if (bytes_read > 0) {
      argoffset += bytes_read;
      // Replace the '\0' with spaces between the args
      cmd->args[(argoffset - 1) & COMMAND_ARGS_MAX_BYTES - 1] = ' ';
    }

    // Prevent this value from being zero'd out when it is exactly max size
    if (argoffset != COMMAND_ARGS_MAX_BYTES)
      argoffset = argoffset & COMMAND_ARGS_MAX_BYTES - 1;
  }
  // Finalize string with '\0'
  cmd->args[(argoffset - 1) & COMMAND_ARGS_MAX_BYTES - 1] = '\0';
  log_printk("args full %d - %s", argoffset, cmd->args);

  bpf_map_update_elem(&commands, &current_tgid, cmd, BPF_ANY);

  struct command_event* e = bpf_map_lookup_elem(&commandevent_heap, &zero);
  if (!e)
    return 0;

  // Command just started.  Send event
  e->event_type = SSHTRACE_EVENT_COMMAND_START;
  e->ptm_pid = conn->ptm_tgid;
  bpf_core_read(&e->cmd, sizeof(struct command), cmd);

  push_event(ctx, e, sizeof(struct command_event));

  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int sys_enter_execveat(struct trace_event_raw_sys_enter* ctx) { return sys_enter_exec_common(ctx); }

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter* ctx) { return sys_enter_exec_common(ctx); }

SEC("tracepoint/syscalls/sys_enter_exit_group")
int sys_enter_exit_group(struct trace_event_raw_sys_enter* ctx) {
  //	field:int error_code;	offset:16;	size:8;	signed:0;

  u32 error_code = (u32) BPF_CORE_READ(ctx, args[0]);
  u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
  struct command* cmd;
  struct connection* conn;

  conn = bpf_map_lookup_elem(&connections, &current_tgid);
  if (conn != NULL) {
    conn->end_time = bpf_ktime_get_ns();

    log_printk("CONNECTION EVENT!!!!");

    bpf_map_delete_elem(&connections, &current_tgid);

    // Connection was terminated, send event
    int zero = 0;
    struct connection_event* e = bpf_map_lookup_elem(&connectionevent_heap, &zero);
    if (!e)
      return 0;
    e->event_type = SSHTRACE_EVENT_CLOSE_CONNECTION;
    e->ptm_pid = conn->ptm_tgid;
    e->conn = *conn;
    push_event(ctx, e, sizeof(struct connection_event));

    return 0;
  }

  cmd = bpf_map_lookup_elem(&commands, &current_tgid);
  if (cmd != NULL) {
    cmd->end_time = bpf_ktime_get_ns();
    cmd->exit_code = error_code;
    log_printk("COMMAND EVENT!!!! conn tgid: %d, tgid: %d - %s", cmd->conn_tgid, current_tgid, cmd->filename);
    log_printk("COMMAND EVENT!!!! %d %s", cmd->stdout_offset, cmd->stdout);

    bpf_map_delete_elem(&commands, &current_tgid);

    // Command just completed.  Send event
    int zero = 0;
    struct command_event* e = bpf_map_lookup_elem(&commandevent_heap, &zero);
    if (!e)
      return 0;

    e->event_type = SSHTRACE_EVENT_COMMAND_END;
    e->ptm_pid = cmd->conn_tgid;

    bpf_core_read(&e->cmd, sizeof(struct command), cmd);

    push_event(ctx, e, sizeof(struct command_event));

    return 0;
  }

  return 1;
}
#define __max(a, b)                                                                                                    \
  ({                                                                                                                   \
    __typeof__(a) _a = (a);                                                                                            \
    __typeof__(b) _b = (b);                                                                                            \
    _a > _b ? _a : _b;                                                                                                 \
  })

#define __min(a, b)                                                                                                    \
  ({                                                                                                                   \
    __typeof__(a) _a = (a);                                                                                            \
    __typeof__(b) _b = (b);                                                                                            \
    _a < _b ? _a : _b;                                                                                                 \
  })

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter* ctx) {
  // args documented here: https://mozillazg.com/2022/05/ebpf-libbpf-tracepoint-common-questions-en.html
  // field:unsigned int fd;	offset:16;	size:8;	signed:0;
  // field:const char * buf;	offset:24;	size:8;	signed:0;
  // field:size_t count;	offset:32;	size:8;	signed:0;

  unsigned int fd = (uint32_t) BPF_CORE_READ(ctx, args[0]);

  if (fd != STDOUT_FILENO && fd != STDERR_FILENO)
    return 1;

  u32 current_tgid = bpf_get_current_pid_tgid() >> 32;
  struct command* cmd;
  cmd = bpf_map_lookup_elem(&commands, &current_tgid);

  if (cmd == NULL)
    return 1;

  // We have a command.  Let's see if we need to copy the buffer
  if (cmd->stdout_offset >= STDOUT_MAX_BYTES) {
    // already collected max amount of bytes for this process
    return 1;
  }

  const char* buf = (const char*) BPF_CORE_READ(ctx, args[1]);
  size_t size = (size_t) BPF_CORE_READ(ctx, args[2]);

  int offset = cmd->stdout_offset;
  offset = __max(offset, 0);
  // Subtract one so that the final '\0' is not copied, since these buffers must append
  int amount_to_write = __min(size, STDOUT_MAX_BYTES - offset);
  amount_to_write = __max(amount_to_write, 0);

  if (amount_to_write == 0)
    return 1;

  // Need this check to get pass the bpf verifier (otherwise it complains about unbounded memory access)
  // Caveat is that STDOUT_MAX_BYTES MUST be a power of 2
  //if (proc_with_offset > proc_output && proc_with_offset < proc_output+amount_to_write)

  offset = offset & STDOUT_MAX_BYTES - 1;
  char* proc_with_offset = cmd->stdout + offset;

  amount_to_write = amount_to_write & STDOUT_MAX_BYTES - 1;

  //if (offset + amount_to_write < STDOUT_MAX_BYTES - 1 )
  bpf_core_read_user(proc_with_offset, amount_to_write, buf);

  // Apply a null termination at the end.  If another write appends, this will get overwritten
  cmd->stdout[offset + amount_to_write] = '\0';

  log_printk("sys_enter_writex pid %d fd %d %s", current_tgid, fd, cmd->stdout + offset);
  log_printk("sys_enter_write wrote %d bytes at offset %d to pid %d", amount_to_write, offset, current_tgid);

  cmd->stdout_offset += amount_to_write;

  //log_printk("sys_enter_write id: %d, fd: %d: %s", conn->ptm_tgid, fd, buf);

  return 0;
}

// Rate limit prevents a huge data spike of terminal data from one or more sessions
// (e.g., local ssh running find /) from blowing out the perf buffer.
static int is_rate_limited(void* ctx, struct connection* conn, int32_t new_bytes, u32 parent_tgid) {
  // Break the rate limit down into 250ms increments so that it doesn't feel as jittery
  // when rate limits hit
  const int TIME_INTERVALS_PER_SECOND = 4;

  const int64_t NANOSECONDS_IN_A_SECOND = 1000000000;
  int64_t cur_epoch_sec = bpf_ktime_get_ns() / (NANOSECONDS_IN_A_SECOND / TIME_INTERVALS_PER_SECOND);
  if (cur_epoch_sec != conn->rate_limit_epoch_second) {
    // We've entered a new second.  Reset all the counters
    conn->rate_limit_epoch_second = cur_epoch_sec;
    conn->rate_limit_hit = false;
    conn->rate_limit_total_bytes_this_second = 0;
  }

  conn->rate_limit_total_bytes_this_second += new_bytes;
  //log_printk("rate limit sec %d bytes %d", conn->rate_limit_epoch_second, conn->rate_limit_total_bytes_this_second);
  if (conn->rate_limit_total_bytes_this_second > (RATE_LIMIT_MAX_BYTES_PER_SECOND / TIME_INTERVALS_PER_SECOND)) {
    // Rate limit.  If limit has already been hit this second, just exit
    // if not, send an event message back with the rate limit message
    if (!conn->rate_limit_hit) {
      conn->rate_limit_hit = true;
      log_printk("rate limit hit for conn %d", conn->ptm_tgid);

      int zero = 0;
      struct terminal_update_event* e = bpf_map_lookup_elem(&terminalupdateevent_heap, &zero);
      if (!e)
        return 0;

      e->event_type = SSHTRACE_EVENT_TERMINAL_UPDATE;
      e->ptm_pid = parent_tgid;
      // Got to love the BPF verifier.  Simple strcpy is not so easy
      e->terminal_data[0] = '[';
      e->terminal_data[1] = '[';
      e->terminal_data[2] = 'S';
      e->terminal_data[3] = 'S';
      e->terminal_data[4] = 'H';
      e->terminal_data[5] = 'B';
      e->terminal_data[6] = 'o';
      e->terminal_data[7] = 'u';
      e->terminal_data[8] = 'n';
      e->terminal_data[9] = 'c';
      e->terminal_data[10] = 'e';
      e->terminal_data[11] = 'r';
      e->terminal_data[12] = ' ';
      e->terminal_data[13] = 'R';
      e->terminal_data[14] = 'a';
      e->terminal_data[15] = 't';
      e->terminal_data[16] = 'e';
      e->terminal_data[17] = '/';
      e->terminal_data[18] = 's';
      e->terminal_data[19] = 'e';
      e->terminal_data[20] = 'c';
      e->terminal_data[21] = ' ';
      e->terminal_data[22] = 'R';
      e->terminal_data[23] = 'e';
      e->terminal_data[24] = 'a';
      e->terminal_data[25] = 'c';
      e->terminal_data[26] = 'h';
      e->terminal_data[27] = 'e';
      e->terminal_data[28] = 'd';
      e->terminal_data[29] = ']';
      e->terminal_data[30] = ']';
      e->terminal_data[31] = '\r';
      e->terminal_data[32] = '\n';
      e->terminal_data[33] = '\0';
      e->data_len = 34;

      push_event(ctx, e, sizeof(struct terminal_update_event));
    }
    return 1;
  }
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter* ctx) {

  // field:unsigned int fd;  offset:16;      size:8; signed:0;
  // field:char * buf;       offset:24;      size:8; signed:0;
  // field:size_t count;     offset:32;      size:8; signed:0;

  u32 fd = (uint32_t) BPF_CORE_READ(ctx, args[0]);

  // Quick/efficient check to bounce out early without having to lookup connection ID
  // We will never be reading non SSHD process nor stdin/stdout/stderr
  if (fd == STDERR_FILENO || fd == STDOUT_FILENO || fd == STDIN_FILENO || !proc_is_sshd())
    return 1;

  // We want to catch the pts process which pipes all reads out to the /dev/ptsx fd
  u32 parent_tgid = get_parent_pid() >> 32;

  struct connection* conn = bpf_map_lookup_elem(&connections, &parent_tgid);

  if (conn != NULL) {
    if (conn->pts_fd == fd || conn->pts_fd2 == fd || conn->pts_fd3 == fd) {
      // Check if this should be rate limited
      if (is_rate_limited(ctx, conn, 0, parent_tgid)) {
        return 0;
      }
      //const char* buf = (const char*) BPF_CORE_READ(ctx, args[1]);
      size_t size = (size_t) BPF_CORE_READ(ctx, args[2]);

      struct read_buffer_map readmap = {0};
      readmap.fd = fd;
      readmap.data_ptr = (void*) ctx->args[1];

      bpf_map_update_elem(&connections_read_mapping, &parent_tgid, &readmap, BPF_ANY);
    }
  }

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit* ctx) {

  // Quick/efficient check to bounce out early without having to lookup connection ID
  // We will never be reading non SSHD process nor stdin/stdout/stderr
  if (!proc_is_sshd())
    return 1;

  int32_t ret = (int32_t) BPF_CORE_READ(ctx, ret);

  // We want to catch the pts process which pipes all reads out to the /dev/ptsx fd
  u32 parent_tgid = get_parent_pid() >> 32;

  struct read_buffer_map* readmap = bpf_map_lookup_elem(&connections_read_mapping, &parent_tgid);

  if (readmap != NULL && readmap->data_ptr != NULL && ret > 0) {

    struct connection* conn = bpf_map_lookup_elem(&connections, &parent_tgid);
    if (conn == NULL)
      return 0;
    // Check if this should be rate limited
    if (is_rate_limited(ctx, conn, ret, parent_tgid)) {
      return 0;
    }

    int zero = 0;
    struct terminal_update_event* e = bpf_map_lookup_elem(&terminalupdateevent_heap, &zero);
    if (!e)
      return 0;

    e->event_type = SSHTRACE_EVENT_TERMINAL_UPDATE;
    e->data_len = ret;
    e->ptm_pid = parent_tgid;

    //static char read_buffer[CONNECTION_READ_BUFFER_BYTES] = {0};
    // Not a CORE read, but I think it is ok because readmap struct is defined in this code
    bpf_probe_read_user(e->terminal_data, ret & (CONNECTION_READ_BUFFER_BYTES - 1), readmap->data_ptr);

    // Set the last char of the string to 0 in case it wasn't set.
    e->terminal_data[ret & (CONNECTION_READ_BUFFER_BYTES - 1)] = '\0';
    log_printk("sys_enter_readz exit ret %d %s", ret, e->terminal_data);

    bpf_map_delete_elem(&connections_read_mapping, &parent_tgid);
    // e.pts_pid = pid_tgid;
    // e.bash_pid = child_tgid;
    // e.ptm_pid = get_parent_pid() >> 32;
    push_event(ctx, e, sizeof(struct terminal_update_event));
  }
  return 0;
}
