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

#ifndef SSHTRACE_TYPES_H
#define SSHTRACE_TYPES_H

#ifndef __clang__
// Only include this for outside BPF code.  BPF code compiles w/ clang
#include <stdint.h>
#endif

// Read buffer bytes must be a power of 2
#define CONNECTION_READ_BUFFER_BYTES 16384

#define SSHTRACE_FILENAME_MAX 255
#define FILEPATH_MAX 4096
#define USERNAME_MAX_LENGTH 32

#define RATE_LIMIT_MAX_BYTES_PER_SECOND 1024000

struct tcpinfo {
  uint32_t server_ip;
  uint32_t client_ip;
  uint16_t server_port;
  uint16_t client_port;
};

struct connection {
  int32_t ptm_tgid;
  int32_t pts_tgid;
  int32_t shell_tgid;
  int32_t tty_id;
  //   uint64_t sent;
  //   uint64_t received;

  struct tcpinfo tcp_info;

  int32_t user_id;
  char username[USERNAME_MAX_LENGTH + 1];

  //   int auth_succesful;
  uint64_t start_time;
  uint64_t end_time;

  // File descriptor for the /dev/pts/x handle.
  // Userspace will need to update these values
  int32_t pts_fd;
  int32_t pts_fd2;
  int32_t pts_fd3;

  // Rate limit terminal updates based on bytes/second
  int64_t rate_limit_epoch_second;
  bool rate_limit_hit;
  int64_t rate_limit_total_bytes_this_second;
};

// Must be a power of 2
#define STDOUT_MAX_BYTES 4096
// Due to weird behavior in the bpf verifier, we double the buffer size to allow
// us to copy Otherwise, it fails to compile complaining about writing outside
// of memory bounds
// TODO: Figure out how to fix this wasted memory.
#define STDOUT_ACTUAL_MEM_USAGE_BYTES STDOUT_MAX_BYTES * 2
#define COMMAND_ARGS_MAX_BYTES 2048
#define COMMAND_ARGS_ACTUAL_MEM_USAGE_BYTES COMMAND_ARGS_MAX_BYTES * 2

struct command {
  char filename[SSHTRACE_FILENAME_MAX];
  uint64_t start_time;
  uint64_t end_time;

  uint32_t stdout_offset;
  char stdout[STDOUT_ACTUAL_MEM_USAGE_BYTES];
  char args[COMMAND_ARGS_ACTUAL_MEM_USAGE_BYTES];

  uint32_t parent_tgid;
  uint32_t current_tgid;

  int32_t exit_code;

  uint32_t conn_tgid;
};

#endif