/*
 * Copyright 2023- by Open Kilt LLC. All rights reserved.
 * This file is part of the SSHLog Software (SSHLog)
 * Licensed under the Redis Source Available License 2.0 (RSALv2)
 */

#ifndef SSHLOG_PTS_PARSER_H
#define SSHLOG_PTS_PARSER_H

#include "../bpf/sshtrace_types.h"
#include <stdint.h>
#include <vector>

namespace sshlog {

#define PTS_UNKNOWN -1

class PtsParser {
 public:
  PtsParser(int pts_pid);
  virtual ~PtsParser();

  int pts_fd_1;
  int pts_fd_2;
  int pts_fd_3;

  int tty_id;

  int user_id;

  void populate_connection(struct connection* conn);

 private:
  void find_pts_fds(int32_t pid);
  void find_tty_id(int32_t pid, int32_t fd);
  void find_user_id(int32_t pid);
};

} // namespace sshlog
#endif /* SSHLOG_PTS_PARSER_H */
