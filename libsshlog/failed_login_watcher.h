/*
 * Copyright 2026- by CHMOD 700 LLC. All rights reserved.
 * This file is part of the SSHLog Software (SSHLog)
 * Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (AGPLv3)
 */

#ifndef SSHLOG_FAILED_LOGIN_WATCHER_H
#define SSHLOG_FAILED_LOGIN_WATCHER_H

#include "bpf/sshtrace_events.h"
#include <iostream>
#include <thread>

namespace sshlog {

// This class spins up a thread that uses inotify to watch for changes to
// the /var/log/btmp file.  Whenever an authorization fails, this file adds an entry
// We parse this data, and put it into an event struct format and pass it off for serializing

// Define a function type for the callback
typedef void (*FailedAuthCallbackFunction)(struct connection_event, void* context);

class FailedLoginWatcherThread {
 public:
  FailedLoginWatcherThread(FailedAuthCallbackFunction callback, void* context);
  ~FailedLoginWatcherThread();
  void shutdown();

 private:
  FailedAuthCallbackFunction _callback;

  void run();
  std::unique_ptr<std::thread> thread_;
  bool _keep_running;
  void* _context;
};

} // namespace sshlog

#endif // SSHLOG_FAILED_LOGIN_WATCHER_H