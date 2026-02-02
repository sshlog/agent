/*
 * This code runs using bpf in the Linux kernel.
 * Copyright 2026- CHMOD 700 LLC
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

#ifndef SSHTRACE_EVENTS_H
#define SSHTRACE_EVENTS_H

#ifndef __clang__
// Only include this for outside BPF code.  BPF code compiles w/ clang
#include <stdint.h>
#include <string>
#endif

#include "sshtrace_types.h"

#define SSHTRACE_EVENT_NEW_CONNECTION 101
// Triggered from userspace code after conn details have been parsed
#define SSHTRACE_EVENT_ESTABLISHED_CONNECTION 102
#define SSHTRACE_EVENT_CLOSE_CONNECTION 103
#define SSHTRACE_EVENT_AUTH_FAILED_CONNECTION 104

#define SSHTRACE_EVENT_COMMAND_START 201
#define SSHTRACE_EVENT_COMMAND_END 202

// Every time the terminal updates, this pushes the data
#define SSHTRACE_EVENT_TERMINAL_UPDATE 301

#define SSHTRACE_EVENT_FILE_UPLOAD 401
// Signals us to grab additional conn data from userspace
// Only used internally
#define SSHTRACE_EVENT_BASH_CLONED 1

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

#ifndef __clang__
  // Outside of BPF, we'll aggregate this data over a time delta
  // Need a higher limit than what the char buffer allows
  std::string aggregated_data;
#endif
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

struct file_upload_event {
  int32_t event_type;

  uint32_t ptm_pid;

  char target_path[2048];
  uint32_t file_mode;
};

#endif