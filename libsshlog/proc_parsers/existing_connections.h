/*
 * Copyright 2023- by Open Kilt LLC. All rights reserved.
 * This file is part of the SSHLog Software (SSHLog)
 * Licensed under the Redis Source Available License 2.0 (RSALv2)
 */

#ifndef SSHLOG_EXISTING_CONNECTIONS_H
#define SSHLOG_EXISTING_CONNECTIONS_H

#include <stdint.h>
#include <string>
#include <vector>

namespace sshlog {

#define SSH_SESSION_UNKNOWN -1

struct ssh_session {
  int32_t pts_pid;
  int32_t ptm_pid;
  int32_t bash_pid;

  uint32_t client_port;
  uint32_t server_port;
  std::string client_ip;
  std::string server_ip;

  uint32_t user_id;

  uint64_t start_time;
};

class ExistingConnections {
public:
  ExistingConnections();
  virtual ~ExistingConnections();

  std::vector<struct ssh_session> get_sessions();

private:
  std::vector<struct ssh_session> sessions;
};

} // namespace sshlog
#endif /* SSHLOG_EXISTING_CONNECTIONS_H */
