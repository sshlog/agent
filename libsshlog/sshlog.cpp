
#include "sshlog.h"
#include "sshtrace_wrapper.h"
#include <plog/Appenders/ColorConsoleAppender.h>
#include <plog/Formatters/TxtFormatter.h>
#include <plog/Init.h>
#include <plog/Log.h>

using namespace sshlog;

SSHBOUNCER* sshlog_init(sshlog_options* options) {
  struct sshlog_options default_options = sshlog_get_default_options();
  if (options == nullptr) {
    options = &default_options;
  }

  //static plog::RollingFileAppender<plog::CsvFormatter> fileAppender("/var/log/sshlog.log", 8000, 3); // Create the 1st appender.
  static plog::ColorConsoleAppender<plog::TxtFormatter> consoleAppender; // Create the 2nd appender.
  plog::init((plog::Severity) options->log_level, &consoleAppender); // Initialize the logger with the both appenders

  PLOG_DEBUG << "Initialized logging";
  SSHTraceWrapper* wrapper = new SSHTraceWrapper();

  return wrapper;
}

sshlog_options sshlog_get_default_options() {
  sshlog_options opt;
  opt.log_level = SSHBOUNCER_LOG_LEVEL::LOG_OFF;
  return opt;
}

// Returns JSON encoded event data
char* sshlog_event_poll(SSHBOUNCER* instance, int timeout_ms) {
  SSHTraceWrapper* wrapper = (SSHTraceWrapper*) instance;
  if (wrapper->is_ok()) {
    char* json_data = wrapper->poll(timeout_ms);

    return json_data;
  } else {
    printf("WRAPPER IS NOT OK!\n");
  }

  return nullptr;
}

int sshlog_is_ok(SSHBOUNCER* instance) {
  SSHTraceWrapper* wrapper = (SSHTraceWrapper*) instance;
  return !wrapper->is_ok();
}

// Releases the memory for the event data string
void sshlog_event_release(char* json_event_data) { free(json_event_data); }

void sshlog_release(SSHBOUNCER* instance) { delete (SSHTraceWrapper*) instance; }