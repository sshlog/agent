#ifndef SSHTRACE_EVENTS_H
#define SSHTRACE_EVENTS_H

#ifndef __clang__
// Only include this for outside BPF code.  BPF code compiles w/ clang
#include <stdint.h>
#endif

#include "sshtrace_types.h"

#define SSHTRACE_EVENT_NEW_CONNECTION 1
#define SSHTRACE_EVENT_CLOSE_CONNECTION 2
#define SSHTRACE_EVENT_COMMAND_START 3
#define SSHTRACE_EVENT_COMMAND_END 4
// Signals us to grab additional conn data from userspace
#define SSHTRACE_EVENT_BASH_CLONED 5
// Every time the terminal updates, this pushes the data
#define SSHTRACE_EVENT_TERMINAL_UPDATE 6

struct event {
  int32_t event_type;
  // int ppid;
  // unsigned exit_code;
  // unsigned long long duration_ns;
  // char comm[TASK_COMM_LEN];
  // char filename[MAX_FILENAME_LEN];
  // bool exit_event;
};

struct bash_clone_event {
  int32_t event_type;

  uint32_t ptm_pid;
  uint32_t pts_pid;
  uint32_t bash_pid;
};

struct terminal_update_event {
  int32_t event_type;

  uint32_t ptm_pid;
  char terminal_data[CONNECTION_READ_BUFFER_BYTES];
  int32_t data_len;
};

struct connection_event {
  int32_t event_type;

  uint32_t ptm_pid;

  struct connection conn;
};

struct command_event {
  int32_t event_type;

  uint32_t ptm_pid;

  struct command cmd;
};

#endif