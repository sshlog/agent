#include "pts_parser.h"
#include "pfs/procfs.hpp"
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <plog/Log.h>
#include <pwd.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sshbouncer {

PtsParser::PtsParser(int pts_pid) {
  this->pts_fd_1 = PTS_UNKNOWN;
  this->pts_fd_2 = PTS_UNKNOWN;
  this->pts_fd_3 = PTS_UNKNOWN;
  this->tty_id = PTS_UNKNOWN;
  this->user_id = PTS_UNKNOWN;

  find_pts_fds(pts_pid);
  find_user_id(pts_pid);
  if (this->pts_fd_1 != PTS_UNKNOWN) {
    find_tty_id(pts_pid, this->pts_fd_1);
  } else {
    // This is not a TTY, so it could either be a one-off command
    // or it could be a SCP.
  }
}

PtsParser::~PtsParser() {}

// static int handle_event(void *ctx, void *data, size_t data_sz)
static bool starts_with(const char* prefix, const char* fullstring) {
  return strncmp(prefix, fullstring, strlen(prefix)) == 0;
}

void PtsParser::find_pts_fds(int32_t pid) {
  int found_handles = 0;

  char dir_path[256];
  char file_path[512];
  snprintf(dir_path, sizeof(dir_path), "/proc/%d/fd/", pid);

  struct stat file_info;

  PLOG_VERBOSE << "pts_parser Searching dir " << dir_path;

  DIR* d;
  struct dirent* dir;
  const int num_fds = 3;
  int pts_fds[num_fds];

  d = opendir(dir_path);
  if (d) {
    while ((dir = readdir(d)) != NULL) {

      snprintf(file_path, sizeof(file_path), "%s%s", dir_path, dir->d_name);
      lstat(file_path, &file_info);

      if ((file_info.st_mode & S_IFMT) == S_IFLNK) {

        char buf[1024];
        size_t len;
        if ((len = readlink(file_path, buf, sizeof(buf) - 1)) != -1) {
          buf[len] = '\0';
          PLOG_VERBOSE << "Symlink found at " << buf;

          if (starts_with("/dev/ptmx", buf) || starts_with("/dev/pts/", buf)) {
            PLOG_DEBUG << "ptmx handle identified";
            // Expecting only 3 pts handles
            if (found_handles >= num_fds)
              PLOG_WARNING << "unexpected number of FDs";
            else
              pts_fds[found_handles++] = strtol(dir->d_name, NULL, 10);
          }
        }
      }
    }
    closedir(d);
  }
  if (found_handles > 0) {
    this->pts_fd_1 = pts_fds[0];
    this->pts_fd_2 = pts_fds[1];
    this->pts_fd_3 = pts_fds[2];
  }
}

void PtsParser::find_tty_id(int32_t pid, int32_t fd) {
  // This can be done by looking into /proc/[pid]/fdinfo/[pts_fd] and parsing
  // the file on newer kernels there is an entry for tty ID

  std::stringstream ss;
  ss << "/proc/" << pid << "/fdinfo/" << fd;
  std::string fdinfo_file = ss.str();

  if (access(fdinfo_file.c_str(), F_OK) != 0) {
    PLOG_WARNING << "Error accessing fdinfo file" << fdinfo_file;
    return;
  }
  std::ifstream file(fdinfo_file);
  std::string line;

  PLOG_DEBUG << "Looking for TTY index: " << fdinfo_file;
  const char* tty_index_key = "tty-index";
  while (std::getline(file, line)) {
    std::stringstream linestream(line);
    std::string val1;
    std::string val2;

    // split the values on whitespace
    // Looking for a line that says tty-index:\t[0-9]+
    // Only available on new-ish Linux versions

    linestream >> val1 >> val2;

    if (strncmp(val1.c_str(), tty_index_key, strlen(tty_index_key)) == 0 && val2.length() == 1) {
      this->tty_id = stoi(val2);
      PLOG_DEBUG << "Found TTY ID: " << this->tty_id;
    }
  }
}

void PtsParser::find_user_id(int32_t pid) {
  // Given the PTS PID, return the user ID
  pfs::procfs pfs;
  pfs::task process = pfs.get_task(pid);
  this->user_id = process.get_status().uid.real;
}

static std::string getUser(uid_t uid) {
  struct passwd* pws;
  pws = getpwuid(uid);
  return pws->pw_name;
}

void PtsParser::populate_connection(struct connection* conn) {
  conn->pts_fd = this->pts_fd_1;
  conn->pts_fd2 = this->pts_fd_2;
  conn->pts_fd3 = this->pts_fd_3;
  conn->user_id = this->user_id;
  strcpy(conn->username, getUser(conn->user_id).c_str());
  conn->tty_id = this->tty_id;
}
} // namespace sshbouncer