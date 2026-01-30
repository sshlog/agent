# Copyright 2023- by Open Kilt LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the Redis Source Available License 2.0 (RSALv2)

import argparse
import logging
from logging.handlers import RotatingFileHandler
from comms.mq_server import MQLocalServer
import sys
import os
from sshlog import SSHLog
from trackers.tracker import Tracker
from events.event_bus import eventbus_sshtrace_push
from plugins.common.plugin_manager import PluginManager
from comms.mq_base import PROC_LOCK_FILE
from comms.pidlockfile import PIDLockFile, LockTimeout, AlreadyLocked
import platform
from web_server import SSHLogWebServer

def run_main():

    parser = argparse.ArgumentParser(description="SSHLog Daemon")

    parser.add_argument("-l", "--logfile", default=None, help='Path to log file')

    # parser.add_argument("-k", "--key", default=os.getenv('OPENREPO_APIKEY', ''), help='API key')
    # parser.add_argument("-s", "--server", default=os.getenv('OPENREPO_SERVER', 'http://localhost:7376'),
    #                     help="OpenRepo Server")

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Print debug info'
    )
    parser.add_argument(
        '--enable-diagnostic-web',
        action='store_true',
        help='Enable the diagnostic web interface'
    )
    parser.add_argument(
        '--diagnostic-web-ip',
        default='127.0.0.1',
        help='Binding IP for the diagnostic web interface (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--diagnostic-web-port',
        default=5000,
        type=int,
        help='Port for the diagnostic web interface (default: 5000)'
    )

    args = parser.parse_args()

    # create logger
    logger = logging.getLogger('sshlog_daemon')

    if args.logfile is not None:
        dirpath = os.path.dirname(args.logfile)
        if not os.path.isdir(dirpath):
            os.makedirs(dirpath)
        if not os.path.isdir(dirpath):
            print(f"Unable to create log directory {dirpath}\nexiting.")
            return
        # add a rotating handler
        handler = RotatingFileHandler(args.logfile, maxBytes=5000000,
                                      backupCount=5)
        formatter = logging.Formatter('%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s')
    else:
        handler = logging.StreamHandler(stream=sys.stdout)
        formatter = logging.Formatter('%(message)s')

    if args.debug:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)


    handler.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(handler)

    try:
        MIN_KERNEL_VER_MAJOR = 5
        MIN_KERNEL_VER_MINOR = 4
        # Do a simple check on the kernel version.  Print a warning if it's too low, but allow to continue
        kernel_ver = platform.uname().release.split('.')
        major_ver = int(kernel_ver[0])
        minor_ver = int(kernel_ver[1])

        if major_ver < MIN_KERNEL_VER_MAJOR or (major_ver == MIN_KERNEL_VER_MAJOR and minor_ver < MIN_KERNEL_VER_MINOR):
            # in case this is not a reliable way to detect compatibility, just log it and allow to continue,
            # but this should make troubleshooting easier if it crashes
            logger.warning(f"WARNING: Your kernel version ({major_ver}.{minor_ver}) "
                  f"is less than the minimum required kernel version {MIN_KERNEL_VER_MAJOR}.{MIN_KERNEL_VER_MINOR}")
    except:
        pass

    # Create Tracker
    session_tracker = Tracker()

    # Load config files from /etc/sshlog/sshlog.yaml as well as any files in /etc/sshlog/conf.d/
    CONF_D_DIR = '/etc/sshlog/conf.d/'
    conf_files = ['/etc/sshlog/sshlog.yaml']
    if os.path.isdir(CONF_D_DIR):
        for conf_file in os.listdir(CONF_D_DIR):
            if conf_file.endswith('.yaml') or conf_file.endswith('.yml'):
                conf_files.append(os.path.join(CONF_D_DIR, conf_file))

    # Initialize the plugins
    plugin_manager = PluginManager(conf_files,
                                   session_tracker,
                                   user_plugin_dirs=['/etc/sshlog/plugins/'])
    if not plugin_manager.plugins_ok():
        for validation_error in plugin_manager.validation_errors:
            logger.warning(validation_error)
        logger.error("Unable to load plugins due to configuration issues. Exiting")
        return
    plugin_manager.initialize_plugins()


    # Spin up local MQ server to start listening
    server = MQLocalServer(session_tracker)
    server.start()

    # Start the Web Server
    web_server = None
    if args.enable_diagnostic_web:
        web_server = SSHLogWebServer(session_tracker, host=args.diagnostic_web_ip, port=args.diagnostic_web_port)
        web_server.start()

    with SSHLog(loglevel=0) as sshb:

        try:
            while sshb.is_ok():
                event_data = sshb.poll(timeout_ms=15)
                if event_data is not None:
                    eventbus_sshtrace_push(event_data, session_tracker)
                    if web_server:
                        web_server.process_event(event_data)
        except KeyboardInterrupt:
            pass

    server.shutdown()
    plugin_manager.shutdown()


if __name__ == "__main__":

    if os.geteuid() != 0:
        print("You must have root privileges to run the daemon.\nPlease try again as root or use 'sudo'.")
        sys.exit(1)

    try:
        with PIDLockFile(PROC_LOCK_FILE, timeout=0.2):
            run_main()
    except (LockTimeout, AlreadyLocked):
        print(f"Error: sshlog daemon is already running.  To force process to run, delete {PROC_LOCK_FILE}")
    except PermissionError:
        print(f"Permission denied accessing file {PROC_LOCK_FILE}")
