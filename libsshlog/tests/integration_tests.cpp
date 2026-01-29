#define CATCH_CONFIG_MAIN
#include <catch2/catch_all.hpp>

#include "sshlog.h"
#include "yyjson.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

// --- CONFIGURATION ---
const std::string SSH_HOST = "127.0.0.1";
const std::string SSH_USER = "mhill";
const std::string SSH_KEY = "/home/mhill/.ssh/id_rsa";

// --- HELPER: UUID GENERATOR ---
std::string generate_uuid() {
  static int i = 0;
  return "token_" + std::to_string(time(NULL)) + "_" + std::to_string(i++);
}

struct JsonView {
  yyjson_val* node;
  JsonView(yyjson_val* v) : node(v) {}

  // --- Navigation ---
  JsonView operator[](const char* key) const { return JsonView(yyjson_obj_get(node, key)); }

  // --- String Comparison ---
  bool operator==(const std::string& expected) const {
    return node && yyjson_is_str(node) && std::string(yyjson_get_str(node)) == expected;
  }

  bool operator!=(const std::string& expected) const { return !(*this == expected); }

  bool contains(const std::string& substring) const {
    if (!node || !yyjson_is_str(node))
      return false;
    std::string val = yyjson_get_str(node);
    return val.find(substring) != std::string::npos;
  }

  // --- Integer Comparison Logic (The Core Fix) ---
  // We strictly compare int64_t vs uint64_t to avoid wrap-around bugs.

  bool operator==(int64_t expected) const {
    if (!node)
      return false;
    if (yyjson_is_int(node))
      return yyjson_get_int(node) == expected;
    if (yyjson_is_uint(node)) {
      if (expected < 0)
        return false; // Unsigned JSON can't equal negative C++ int
      return yyjson_get_uint(node) == (uint64_t) expected;
    }
    return false;
  }

  bool operator!=(int64_t expected) const { return !(*this == expected); }

  bool operator<(int64_t expected) const {
    if (!node)
      return false;
    if (yyjson_is_int(node))
      return yyjson_get_int(node) < expected;
    if (yyjson_is_uint(node)) {
      if (expected < 0)
        return false; // Unsigned (pos) can never be less than negative
      return yyjson_get_uint(node) < (uint64_t) expected;
    }
    return false;
  }

  bool operator>(int64_t expected) const {
    if (!node)
      return false;
    if (yyjson_is_int(node))
      return yyjson_get_int(node) > expected;
    if (yyjson_is_uint(node)) {
      if (expected < 0)
        return true; // Unsigned (pos) is always greater than negative
      return yyjson_get_uint(node) > (uint64_t) expected;
    }
    return false;
  }

  bool operator<=(int64_t expected) const { return !(*this > expected); }
  bool operator>=(int64_t expected) const { return !(*this < expected); }

  // Overloads for plain 'int' to resolve ambiguity
  bool operator==(int v) const { return *this == (int64_t) v; }
  bool operator!=(int v) const { return *this != (int64_t) v; }
  bool operator<(int v) const { return *this < (int64_t) v; }
  bool operator>(int v) const { return *this > (int64_t) v; }
  bool operator<=(int v) const { return *this <= (int64_t) v; }
  bool operator>=(int v) const { return *this >= (int64_t) v; }

  // --- Existence Check ---
  operator bool() const { return node != nullptr; }
  // Helper to extract string value
  std::string get_string() const {
    if (node && yyjson_is_str(node))
      return yyjson_get_str(node);
    return "";
  }

  // Helper to extract int value
  int64_t get_int() const {
    if (node && yyjson_is_int(node))
      return yyjson_get_int(node);
    return 0;
  }
};

// --- LOG BUFFER ---
class LogBuffer {
 private:
  std::vector<std::string> logs;
  std::mutex mtx;

 public:
  void add(const char* json) {
    std::lock_guard<std::mutex> lock(mtx);
    logs.emplace_back(json);
  }

  size_t size() {
    std::lock_guard<std::mutex> lock(mtx);
    return logs.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mtx);
    logs.clear();
  }

  std::vector<std::string> get_snapshot() {
    std::lock_guard<std::mutex> lock(mtx);
    return logs;
  }
};

// --- DAEMON WRAPPER ---
class SSHLogDaemon {
 private:
  SSHLOG* ctx = nullptr;
  std::thread worker;
  std::atomic<bool> stop_flag{false};

 public:
  LogBuffer captured_logs;

  SSHLogDaemon() {
    if (geteuid() != 0) {
      std::cerr << "[-] Must run as root for BPF." << std::endl;
      exit(1);
    }

    sshlog_options opts = sshlog_get_default_options();
    opts.log_level = SSHLOG_LOG_LEVEL::LOG_WARNING;

    ctx = sshlog_init(&opts);
    if (!ctx) {
      std::cerr << "[-] Failed to init sshlog!" << std::endl;
      exit(1);
    }

    worker = std::thread([this]() {
      while (!stop_flag && sshlog_is_ok(ctx) == 0) {
        char* json = sshlog_event_poll(ctx, 50);
        if (json) {
          captured_logs.add(json);
          sshlog_event_release(json);
        }
      }
    });

    // Reduced timeout: 1 second should be enough for BPF to load on most systems
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // 2. DRAIN: Wipe the buffer clean.
    // This ensures tests don't accidentally match stale events from startup.
    std::cout << "[Setup] Draining " << captured_logs.size() << " initial startup events..." << std::endl;
    captured_logs.clear();
  }

  ~SSHLogDaemon() {
    stop_flag = true;
    if (worker.joinable())
      worker.join();
    sshlog_release(ctx);
  }
};

static SSHLogDaemon* daemon_ptr = nullptr;

// --- WAIT HELPER ---
using JsonMatcher = std::function<bool(JsonView root)>;

bool wait_for_event(JsonMatcher matcher, int timeout_sec = 5) {
  auto start = std::chrono::steady_clock::now();
  size_t processed_count = 0;

  while (true) {
    auto logs = daemon_ptr->captured_logs.get_snapshot();

    for (size_t i = processed_count; i < logs.size(); ++i) {
      const std::string& log_line = logs[i];

      yyjson_doc* doc = yyjson_read(log_line.c_str(), log_line.size(), 0);
      if (doc) {
        JsonView root(yyjson_doc_get_root(doc));
        bool matched = matcher(root);
        yyjson_doc_free(doc);

        if (matched) {
          // REQUIREMENT: Print the matching JSON
          std::cout << "\n[MATCH FOUND]: " << log_line << std::endl;
          return true;
        }
      }
    }
    processed_count = logs.size();

    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() > timeout_sec) {
      return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
  return false;
}

// --- TESTS ---

TEST_CASE("SSHLog Library Integration (Strict JSON)", "[lib]") {
  static SSHLogDaemon daemon;
  daemon_ptr = &daemon;

  SECTION("New Connection Detection") {
    INFO("Connecting to " << SSH_HOST);
    std::string cmd = "ssh -o StrictHostKeyChecking=no -i " + SSH_KEY + " " + SSH_USER + "@" + SSH_HOST + " 'exit'";
    std::system(cmd.c_str());

    INFO("Parsing JSON for event_type: 'connection_new'");

    bool found = wait_for_event([](JsonView json) { return json["event_type"] == "connection_new"; });
    CHECK(found == true);

    found = wait_for_event([](JsonView json) { return json["event_type"] == "connection_established"; });
    CHECK(found == true);

    found = wait_for_event([](JsonView json) { return json["event_type"] == "connection_close"; });
    CHECK(found == true);
  }

  SECTION("Command Execution Tracking") {
    std::string token = generate_uuid();
    std::string cmd_str = "ls " + token;
    INFO("Running: " << cmd_str);

    std::string cmd =
        "ssh -o StrictHostKeyChecking=no -i " + SSH_KEY + " " + SSH_USER + "@" + SSH_HOST + " '" + cmd_str + "'";
    std::system(cmd.c_str());

    INFO("Parsing JSON for 'command_start' with token: " << token);

    bool found = false;
    int64_t pid = -1;

    found = wait_for_event([&](JsonView json) {
      // Check for string "command_start" and token inside args
      if ((json["event_type"] == "command_start") && (json["filename"] == "ls") && (json["args"].contains(token)) &&
          (json["exit_code"] == -1)) {
        pid = json["pid"].get_int();
        return true;
      }
      return false;
    });

    CHECK(found == true);

    INFO("Looking for PID " << pid);

    INFO("Parsing JSON for 'command_end' with token: " << token);
    found = wait_for_event([&](JsonView json) {
      // Check for string "command_end" and token inside args
      return (json["event_type"] == "command_finish") && (json["filename"] == "ls") && (json["pid"] == pid) &&
             (json["args"].contains(token)) && (json["exit_code"] != 0) && (json["stdout_size"] > 0);
    });

    CHECK(found == true);
  }

  SECTION("File Upload (SCP) Detection") {
    std::string token = generate_uuid();
    std::string remote_path = "/tmp/sshlog_test_" + token;
    std::system("echo 'payload' > /tmp/sshlog_dummy");

    INFO("Uploading to " << remote_path);
    std::string cmd = "scp -o StrictHostKeyChecking=no -i " + SSH_KEY + " /tmp/sshlog_dummy " + SSH_USER + "@" +
                      SSH_HOST + ":" + remote_path;
    std::system(cmd.c_str());

    INFO("Parsing JSON for 'file_upload' with path: " << remote_path);

    bool found = wait_for_event([&](JsonView json) {
      // Check for string "file_upload"
      // Checks both 'filename' and 'target_path' just in case schema varies
      bool name_match = (json["filename"] == remote_path) || (json["target_path"] == remote_path);

      return (json["event_type"] == "file_upload") && name_match;
    });

    CHECK(found == true);
    std::remove("/tmp/sshlog_dummy");
  }
}

// ... (Previous includes and setup code remain the same) ...

// --- NEW TEST CASES ---

TEST_CASE("SSHLog Advanced Features", "[lib]") {
  static SSHLogDaemon daemon;
  daemon_ptr = &daemon;

  SECTION("Authentication Failure Detection") {
    INFO("Attempting failed login for user 'baduser'");

    // Use -o BatchMode=yes -o PasswordAuthentication=no to fail immediately without prompt
    // We attempt to log in as a non-existent user or just fail auth
    std::string cmd = "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o PasswordAuthentication=no baduser@" +
                      SSH_HOST + " 'exit' 2>/dev/null";

    // We expect the command to fail (ret != 0)
    int ret = std::system(cmd.c_str());
    CHECK(ret != 0);

    INFO("Waiting for 'connection_auth_failed' event");

    bool found = wait_for_event([](JsonView json) {
      return (json["event_type"] == "connection_auth_failed") && (json["username"] == "baduser");
    });

    CHECK(found == true);
  }

  SECTION("Command Output Capture (Stdout)") {
    std::string token = generate_uuid();
    INFO("Running command that generates specific output: " << token);

    // We run a command that prints the token to stdout
    std::string cmd =
        "ssh -o StrictHostKeyChecking=no -i " + SSH_KEY + " " + SSH_USER + "@" + SSH_HOST + " 'ls " + token + "'";
    std::system(cmd.c_str());

    INFO("Waiting for 'command_finish' with stdout containing token");

    bool found = wait_for_event([&](JsonView json) {
      // Check that we captured the stdout
      // Log entry example: {"event_type":"command_finish", ..., "stdout":"token_...\n"}
      return (json["event_type"] == "command_finish") && (json["stdout"].contains(token));
    });

    CHECK(found == true);
  }

  SECTION("Terminal Keystroke Logging") {
    // This is harder to simulate with 'ssh command' because that doesn't allocate a PTY.
    // We use Python/Expect logic via 'script' or just assume 'ssh -tt' works.
    // 'ssh -tt' forces TTY allocation.

    INFO("Simulating interactive terminal session");

    // We send a command that sleeps so the session stays open, then we send input?
    // Actually, just running a command with -tt might trigger terminal_update events
    // for the output, even if we don't send keystrokes manually.
    std::string unique_output = "TERM_DATA_" + generate_uuid();

    std::string cmd = "ssh -tt -o StrictHostKeyChecking=no -i " + SSH_KEY + " " + SSH_USER + "@" + SSH_HOST +
                      " 'echo " + unique_output + "; exit'";
    std::system(cmd.c_str());

    INFO("Waiting for 'terminal_update' containing output");

    bool found = wait_for_event([&](JsonView json) {
      // Look for the echoed text in the terminal stream
      return (json["event_type"] == "terminal_update") && (json["terminal_data"].contains(unique_output));
    });

    CHECK(found == true);
  }

  SECTION("Recursive Command Execution (Shell Chains)") {
    // Your logs showed: sh -c ... -> run-parts -> uname
    // Let's verify we catch a child process spawned by a shell script.

    std::string token = generate_uuid();
    INFO("Running nested command: sh -c 'ls " << token << "'");

    // We run 'sh -c ls' to create a parent-child relationship (sshd -> sh -> ls)
    std::string cmd = "ssh -o StrictHostKeyChecking=no -i " + SSH_KEY + " " + SSH_USER + "@" + SSH_HOST +
                      " 'sh -c \"ls " + token + "\"'";
    std::system(cmd.c_str());

    INFO("Waiting for the child 'ls' command event");

    bool found = wait_for_event([&](JsonView json) {
      // We want to make sure we caught the 'ls', not just the 'sh'
      // The 'filename' should be 'ls' (or contain it) and args should have token
      bool is_ls = (json["filename"] == "ls") || (json["filename"] == "/usr/bin/ls");

      return (json["event_type"] == "command_start") && is_ls && (json["args"].contains(token));
    });

    CHECK(found == true);
  }
}