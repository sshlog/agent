#include "failed_login_watcher.h"
#include <errno.h>
#include <fcntl.h>
#include <plog/Log.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>

#include <iostream>

namespace sshlog {

FailedLoginWatcherThread::FailedLoginWatcherThread(FailedAuthCallbackFunction callback, void* context)
    : _callback(callback), _context(context) {

  this->_keep_running = true;
  thread_ = std::make_unique<std::thread>(&FailedLoginWatcherThread::run, this);
}

FailedLoginWatcherThread::~FailedLoginWatcherThread() {
  // Wait for the thread to finish executing
  this->shutdown();
}

void FailedLoginWatcherThread::shutdown() {
  this->_keep_running = false;
  if (thread_->joinable())
    thread_->join();
}

void FailedLoginWatcherThread::run() {

  const char* BTMP_FILEPATH = "/var/log/btmp";

  struct utmp ut;
  int fd = open(BTMP_FILEPATH, O_RDONLY);
  int inotify_fd = inotify_init1(IN_NONBLOCK);
  inotify_add_watch(inotify_fd, BTMP_FILEPATH, IN_MODIFY);
  time_t last_login = time(NULL);
  const int MILLISECONDS_TO_SLEEP = 10;

  while (this->_keep_running) {
    // Wait for inotify events
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event* event;
    int len;

    len = read(inotify_fd, buf, sizeof(buf));
    if (len == -1 && errno != EAGAIN) {
      PLOG_WARNING << "Unable to read " << BTMP_FILEPATH << ".  Disabling failed auth tracking";
      break;
    }

    // Call parser code on new entries
    lseek(fd, 0, SEEK_SET);
    while (this->_keep_running && read(fd, &ut, sizeof(struct utmp)) == sizeof(struct utmp)) {
      if (ut.ut_type == LOGIN_PROCESS) {
        // Check if entry is new
        if (ut.ut_tv.tv_sec > last_login) {
          // Call parser code

          // char* ctime_no_newline = strtok(ctime((time_t*) &ut.ut_tv.tv_sec), "\n");
          // printf("New login detected: %s host: %s pid: %d at time: %s\n", ut.ut_user, ut.ut_host, ut.ut_pid,
          //        ctime_no_newline);

          // Update last_login time
          last_login = ut.ut_tv.tv_sec;

          int64_t epoch_milliseconds = (((int64_t) ut.ut_tv.tv_sec) * 1000) + (ut.ut_tv.tv_usec / 1000);

          connection_event ce = {0};
          ce.ptm_pid = ut.ut_pid;
          ce.event_type = SSHTRACE_EVENT_AUTH_FAILED_CONNECTION;
          ce.conn.start_time = epoch_milliseconds;
          ce.conn.end_time = epoch_milliseconds;
          ce.conn.pts_tgid = -1;
          ce.conn.shell_tgid = -1;
          ce.conn.tty_id = -1;
          strncpy(ce.conn.username, ut.ut_user, USERNAME_MAX_LENGTH);
          ce.conn.tcp_info.client_ip = ut.ut_addr;
          ce.conn.tcp_info.client_port = 0;

          struct passwd* pw = getpwnam(ut.ut_user);
          if (pw != nullptr) {
            ce.conn.user_id = pw->pw_uid;
          } else {
            // This will happen if they tried to login with a username that doesn't exist.
            ce.conn.user_id = -1;
          }

          this->_callback(ce, _context);
        }
      }
    }
    usleep(MILLISECONDS_TO_SLEEP * 1000);
  }

  close(fd);
  close(inotify_fd);
  this->_keep_running = false;
}

} // namespace sshlog

// // Uncomment to compile a test program that just reports failed login info (for debugging)
// void callback(connection_event failed_login_event, void* context) {
//
//   std::cout << "Login detected: " << failed_login_event.conn.username << " (" << failed_login_event.conn.user_id << ") "
//             << "pid: " << failed_login_event.ptm_pid << " time: " << failed_login_event.conn.start_time << std::endl;
//
//   // printf("login detected: %s host: %s pid: %ld at time:%ld\n", login_info.username.c_str(),
//   //        login_info.ip_address.c_str(), login_info.pid, login_info.time_epoch_ms);
// }

// int main(int argc, const char** argv) {
//
//   sshlog::FailedLoginWatcherThread watcher(callback, nullptr);
//   while (true)
//     usleep(100);
//   return 0;
// }