import argparse
import logging
from comms.mq_server import MQLocalServer
import sys
import os
from sshbouncer import SSHBouncer
from trackers.tracker import Tracker
from events.event_bus import eventbus_sshtrace_push

def run_main():

    parser = argparse.ArgumentParser(description="SSHBouncer Daemon")


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
    ch = logging.StreamHandler(stream=sys.stdout)
    if args.debug:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s')
    else:
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')

    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    # Create Tracker
    session_tracker = Tracker()

    # Spin up local MQ server to start listening
    server = MQLocalServer(session_tracker)
    server.start()

    with SSHBouncer(loglevel=0) as sshb:

        try:
            while sshb.is_ok():
                event_data = sshb.poll(timeout=100)
                if event_data is not None:
                    logger.debug(event_data)
                    eventbus_sshtrace_push(event_data, session_tracker)
        except KeyboardInterrupt:
            pass

    server.shutdown()


if __name__ == "__main__":

    run_main()
