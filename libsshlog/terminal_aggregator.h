/*
 * Copyright 2023- by Open Kilt LLC. All rights reserved.
 * This file is part of the SSHLog Software (SSHLog)
 * Licensed under the Redis Source Available License 2.0 (RSALv2)
 */

#ifndef SSHLOG_TERMINAL_AGGREGATOR_H
#define SSHLOG_TERMINAL_AGGREGATOR_H

#include "bpf/sshtrace_events.h"
#include <chrono>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// Terminal data flows from BPF at a high rate, triggering many events
// This class collapses this data into fewer events by buffering terminal data received within
// milliseconds of each other.  The text is concatenated and the data length is extended

namespace sshlog {

struct aggregated_terminal_event {
  int64_t ptm_pid;
  std::stringstream terminal_data;
  std::chrono::time_point<std::chrono::steady_clock> insert_timestamp;
};

class TerminalAggregator {
 public:
  TerminalAggregator(int max_time_ms) : max_time_ms_(max_time_ms) {}

  void add(const int64_t ptm_pid, const std::string& data) {
    std::lock_guard<std::mutex> guard(map_mutex_);

    auto now = std::chrono::steady_clock::now();
    auto it = map_.find(ptm_pid);
    if (it == map_.end()) {
      map_[ptm_pid] = {};
      map_[ptm_pid].ptm_pid = ptm_pid;
      map_[ptm_pid].terminal_data << data;
      map_[ptm_pid].insert_timestamp = now;
    } else {
      it->second.terminal_data << data;
    }
  }

  std::vector<terminal_update_event> get() {
    std::lock_guard<std::mutex> guard(map_mutex_);

    auto now = std::chrono::steady_clock::now();
    std::vector<terminal_update_event> result;
    for (auto it = map_.begin(); it != map_.end();) {
      auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.insert_timestamp);
      if (diff.count() >= max_time_ms_) {
        terminal_update_event term_update_ev;
        term_update_ev.event_type = SSHTRACE_EVENT_TERMINAL_UPDATE;
        term_update_ev.ptm_pid = it->second.ptm_pid;
        term_update_ev.aggregated_data = it->second.terminal_data.str();
        term_update_ev.data_len = term_update_ev.aggregated_data.length();

        result.push_back(term_update_ev);
        it = map_.erase(it);
      } else {
        ++it;
      }
    }
    return result;
  }

 private:
  int max_time_ms_;
  std::unordered_map<int64_t, struct aggregated_terminal_event> map_;
  std::mutex map_mutex_;
};

} // namespace sshlog

#endif // SSHLOG_TERMINAL_AGGREGATOR_H