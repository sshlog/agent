import argparse
import logging
from logging.handlers import RotatingFileHandler
from comms.mq_server import MQLocalServer
import sys
import os
from sshbouncer import SSHBouncer
from trackers.tracker import Tracker
from events.event_bus import eventbus_sshtrace_push
from plugins.common.plugin_manager import PluginManager

def run_main():

    parser = argparse.ArgumentParser(description="SSHBouncer Daemon")

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
        '-f',
        action='store_true',
        help='Run daemon in the foreground'
    )

    args = parser.parse_args()

    # create logger
    logger = logging.getLogger('sshbouncer_daemon')

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
    else:
        handler = logging.StreamHandler(stream=sys.stdout)

    if args.debug:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s')
    else:
        logger.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')


    handler.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(handler)

    if os.geteuid() != 0:
        logger.warning("You must have root privileges to run the daemon.\nPlease try again as root or use 'sudo'.")
        return

    # Create Tracker
    session_tracker = Tracker()

    # Load config files from /etc/sshbouncer/sshbouncer.yaml as well as any files in /etc/sshbouncer/conf.d/
    CONF_D_DIR = '/etc/sshbouncer/conf.d/'
    conf_files = ['/etc/sshbouncer/sshbouncer.yaml']
    if os.path.isdir(CONF_D_DIR):
        for conf_file in os.listdir(CONF_D_DIR):
            if conf_file.endswith('.yaml') or conf_file.endswith('.yml'):
                conf_files.append(os.path.join(CONF_D_DIR, conf_file))

    # Initialize the plugins
    plugin_manager = PluginManager(conf_files,
                                   session_tracker,
                                   user_plugin_dirs=['/etc/sshbouncer/plugins/'])
    if not plugin_manager.plugins_ok():
        for validation_error in plugin_manager.validation_errors:
            logger.warning(validation_error)
        logger.error("Unable to load plugins due to configuration issues. Exiting")
        return
    plugin_manager.initialize_plugins()


    # Spin up local MQ server to start listening
    server = MQLocalServer(session_tracker)
    server.start()

    with SSHBouncer(loglevel=0) as sshb:

        try:
            while sshb.is_ok():
                event_data = sshb.poll(timeout_ms=15)
                if event_data is not None:
                    eventbus_sshtrace_push(event_data, session_tracker)
        except KeyboardInterrupt:
            pass

    server.shutdown()
    plugin_manager.shutdown()


if __name__ == "__main__":

    run_main()
