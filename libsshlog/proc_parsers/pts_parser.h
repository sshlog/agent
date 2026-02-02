/*
 * Copyright 2026- by CHMOD 700 LLC. All rights reserved.
 * This file is part of the SSHLog Software (SSHLog)
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (AGPLv3)
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
