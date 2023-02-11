
#include "sshbouncer.h"
#include "tclap/CmdLine.h"
#include <iostream>
#include <signal.h>

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

int main(int argc, const char** argv) {

  bool debug_mode = false;

  TCLAP::CmdLine cmd("SSHBouncer Command Line Utility", ' ', "1.0.0");

  TCLAP::SwitchArg debugSwitch("", "debug", "Enable debug output.  Default=off", cmd, false);

  try {
    // cmd.add(somethingArg);

    cmd.parse(argc, argv);

    debug_mode = debugSwitch.getValue();

  } catch (TCLAP::ArgException& e) {
    std::cerr << "error: " << e.error() << " for arg " << e.argId() << std::endl;
    return 1;
  }

  /* Cleaner handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  sshbouncer_options opts = sshbouncer_get_default_options();
  if (debug_mode)
    opts.log_level = SSHBOUNCER_LOG_LEVEL::LOG_DEBUG;
  else
    opts.log_level = SSHBOUNCER_LOG_LEVEL::LOG_WARNING;

  SSHBOUNCER* sshb_inst = sshbouncer_init(&opts);
  while (!exiting && sshbouncer_is_ok(sshb_inst) == 0) {
    char* json_data = sshbouncer_event_poll(sshb_inst, 15);
    if (json_data != nullptr) {
      std::cout << json_data << std::endl;
      sshbouncer_event_release(json_data);
    }
  }

  sshbouncer_release(sshb_inst);
}
