#ifndef SSHBOUNCER_SSHTRACE_WRAPPER_H
#define SSHBOUNCER_SSHTRACE_WRAPPER_H

#include "sshtrace.skel.h"
#include "utility/blockingconcurrentqueue.h"
#include <stdint.h>
#include <thread>

namespace sshbouncer {

// This wrapper initializes the BPF interface
// and polls it in a bg thread.  All data is serialized to JSON and
// popped onto a queue which is made available to the API in the primary thread
// the public "poll" function drains strings from the "q" object that were
// placed there from the bg thread

class SSHTraceWrapper {
 public:
  SSHTraceWrapper();
  virtual ~SSHTraceWrapper();

  char* poll(int timeout_ms = 100);

  bool is_ok() { return bpf_err_code >= 0; }

  // Used by handler
  struct sshtrace_bpf* skel = nullptr;
#ifdef SSHTRACE_USE_RINGBUF
  struct ring_buffer* pb = nullptr;
#else
  struct perf_buffer* pb = nullptr;
#endif
  moodycamel::BlockingConcurrentQueue<char*> q;

  // Called by handler functions to populate the queue with JSON data
  void push(std::string);

  void queue_event(void* event_struct);
  int bpf_err_code;

 private:
  std::unique_ptr<std::thread> bpf_poll_thread;
};

} // namespace sshbouncer
#endif /* SSHBOUNCER_SSHTRACE_WRAPPER_H */
