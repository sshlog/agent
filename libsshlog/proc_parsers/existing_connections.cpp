// Copyright 2023- by Open Kilt LLC. All rights reserved.
// This file is part of the SSHLog Software (SSHLog)
// Licensed under the Redis Source Available License 2.0 (RSALv2)

#include "existing_connections.h"
#include "pfs/procfs.hpp"
#include <iostream>
#include <plog/Log.h>
#include <sys/stat.h>
#include <time.h>
#include <unordered_map>

namespace sshlog {

#define SSHD_DEFAULT_PORT 22
#define SSHD_PROCESS_NAME "sshd"

static bool is_pts(pfs::task& process, std::unordered_map<int32_t, pfs::task> processes);

static int discover_sshd_listen_port(pfs::procfs& pfs, pfs::task& sshd_process);

ExistingConnections::ExistingConnections() {
  pfs::procfs pfs;

  // Build a list of all processes in a hashmap indexed by process ID
  std::unordered_map<int32_t, pfs::task> processes;

  try {
    for (const auto& process : pfs.get_processes()) {
      processes.insert({process.id(), process});
    }
  } catch (const std::exception& e) {
    PLOG_ERROR << "Failed to list processes: " << e.what();
    return;
  }

  int sshd_port = SSHD_DEFAULT_PORT;

  // Find all "sshd" processes
  for (const std::pair<int32_t, pfs::task>& proc_data : processes) {
    pfs::task process = proc_data.second;

    // Processes (especially short-lived ones from exec_stress) can exit
    // after we list them but before we inspect them.
    // We must catch exceptions here to prevent the agent from crashing.
    try {
      if (process.get_comm() != SSHD_PROCESS_NAME)
        continue;

      bool is_pts_target = is_pts(process, processes);
      int ppid = process.get_stat().ppid;

      if (ppid == 1) {
        // This is our sshd process, try and determine the port
        sshd_port = discover_sshd_listen_port(pfs, process);
      }

      if (is_pts_target) {
        struct ssh_session session;

        // I am the pts process, so find the parent (ptm) and child (bash)
        // process
        session.pts_pid = process.id();
        session.ptm_pid = ppid;
        session.bash_pid = SSH_SESSION_UNKNOWN;
        session.client_ip = "";
        session.client_port = SSH_SESSION_UNKNOWN;
        session.server_ip = "";
        session.server_port = SSH_SESSION_UNKNOWN;

        // Convert process start time to CLOCK_MONOTONIC time
        const int64_t NANOS_IN_A_SEC = 1000000000;
        static int64_t JIFFIES_PER_SECOND = sysconf(_SC_CLK_TCK);

        int64_t proc_start_seconds_after_boot = process.get_stat().starttime / JIFFIES_PER_SECOND;
        int64_t proc_start_nanos_after_boot = proc_start_seconds_after_boot * NANOS_IN_A_SEC;

        session.start_time = proc_start_nanos_after_boot;

        const int64_t MILLIS_IN_A_SEC = 1000;
        const int64_t NANOS_IN_A_MILLIS = 1000000;
        struct timespec ts_bt, ts_mt;
        clock_gettime(CLOCK_MONOTONIC, &ts_mt);
        clock_gettime(CLOCK_BOOTTIME, &ts_bt);

        int64_t boottime_diff =
            (ts_bt.tv_sec - ts_mt.tv_sec) * MILLIS_IN_A_SEC + (ts_bt.tv_nsec - ts_mt.tv_nsec) / NANOS_IN_A_MILLIS;
        // PLOG_DEBUG << "existing connection millisecond adjustment: " << boottime_diff;

        session.start_time -= (boottime_diff * NANOS_IN_A_MILLIS);

        session.user_id = process.get_status().uid.real;

        // Iterate the processes and stop at the first process that lists
        // ptm_pid as its parent
        for (const std::pair<int32_t, pfs::task>& child_proc_data : processes) {
          pfs::task child_proc = child_proc_data.second;
          try {
            int child_parent = child_proc.get_stat().ppid;
            if (child_parent == session.pts_pid) {
              session.bash_pid = child_proc.id();
              break;
            }
          } catch (const std::exception& e) {
            // Child process gone? ignore.
          }
        }

        // Find the socket/IP information for this process
        std::unordered_map<int, pfs::task> proc_sockets_by_inode;

        // get_fds() can throw if process is gone
        for (const std::pair<int, pfs::fd>& fd_data : process.get_fds()) {
          try {
            struct stat st = fd_data.second.get_target_stat();
            if (S_ISSOCK(st.st_mode)) {
              proc_sockets_by_inode.insert({st.st_ino, process});
            }
          } catch (...) {
            continue;
          }
        }

        for (auto& net : pfs.get_net().get_tcp()) {
          if (net.local_port == sshd_port && proc_sockets_by_inode.find(net.inode) != proc_sockets_by_inode.end()) {

            session.client_ip = net.remote_ip.to_string();
            session.server_ip = net.local_ip.to_string();
            session.client_port = net.remote_port;
            session.server_port = net.local_port;
          }
        }

        this->sessions.push_back(session);
      }
    } catch (const std::exception& e) {
      // Process likely exited during inspection. Use DEBUG log so we don't spam errors during stress tests.
      PLOG_DEBUG << "Process vanished during inspection (race condition): " << e.what();
      continue;
    }
  }

  for (auto& session : sessions) {
    PLOG_INFO << "Found Existing Session: " << session.ptm_pid << " / " << session.pts_pid << " / " << session.bash_pid
              << " - " << session.server_ip << ":" << session.server_port << " - " << session.client_ip << ":"
              << session.client_port;
  }
}

ExistingConnections::~ExistingConnections() {}

std::vector<struct ssh_session> ExistingConnections::get_sessions() { return this->sessions; }

static bool is_pts(pfs::task& process, std::unordered_map<int32_t, pfs::task> processes) {
  try {
    // Make sure target proc is sshd
    if (process.get_comm() != SSHD_PROCESS_NAME)
      return false;

    // Make sure he has a parent
    int ppid = process.get_stat().ppid;
    if (ppid == 1)
      return false;
    if (processes.find(ppid) == processes.end())
      return false;

    // Parent should also be "sshd"
    pfs::task parent = processes.at(ppid);

    // Check parent details (can throw if parent died)
    int parent_ppid = parent.get_stat().ppid;
    if (parent.get_comm() != SSHD_PROCESS_NAME || parent_ppid == 1)
      return false;

    if (processes.find(parent_ppid) == processes.end())
      return false;

    // Grandparent should exist, and it's PPID should be 1
    pfs::task grandparent = processes.at(parent_ppid);
    int grandparent_ppid = grandparent.get_stat().ppid;
    if (grandparent.get_comm() != SSHD_PROCESS_NAME || grandparent_ppid != 1)
      return false;

    return true;
  } catch (...) {
    // Any failure to read proc files means this isn't a stable SSH session we can inspect
    return false;
  }
}

static int discover_sshd_listen_port(pfs::procfs& pfs, pfs::task& sshd_process) {
  try {
    std::unordered_map<int, pfs::task> proc_sockets_by_inode;
    for (const std::pair<int, pfs::fd>& fd_data : sshd_process.get_fds()) {
      try {
        struct stat st = fd_data.second.get_target_stat();
        if (S_ISSOCK(st.st_mode)) {
          proc_sockets_by_inode.insert({st.st_ino, sshd_process});
        }
      } catch (...) {
        continue;
      }
    }

    for (auto& net : pfs.get_net().get_tcp()) {
      if (proc_sockets_by_inode.find(net.inode) != proc_sockets_by_inode.end() &&
          (net.socket_net_state == pfs::net_socket::net_state::listen)) {

        return net.local_port;
      }
    }
  } catch (...) {
    // Return default if inspection fails
  }

  // If we couldn't determine it, return default port (22)
  return SSHD_DEFAULT_PORT;
}
} // namespace sshlog