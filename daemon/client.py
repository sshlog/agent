import argparse
import logging
import os
import sys
from comms.mq_client import MQClient
from comms.dtos import SessionListRequestDto, SessionListResponseDto
import json
from prettytable import PrettyTable
from prettytable import PLAIN_COLUMNS, SINGLE_BORDER

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="SSHBouncer Command Line Interface")

    #subparsers = parser.add_subparsers(dest='command', help='Available Operations')
    subparsers = parser.add_subparsers(title='Commands', dest='command', help='Available Operations')
    subparsers.required = True

    # parser.add_argument("-k", "--key", default=os.getenv('OPENREPO_APIKEY', ''), help='API key')
    # parser.add_argument("-s", "--server", default=os.getenv('OPENREPO_SERVER', 'http://localhost:7376'),
    #                     help="OpenRepo Server")

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Print debug info'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Print output to JSON'
    )


    # create the parser for the "watch" command
    parser_watch = subparsers.add_parser('watch', help='Watch all live SSH session events')

    # create the parser for the "session" command
    parser_sessions = subparsers.add_parser('sessions', help='List all active sessions')
    sessions_subparsers = parser_sessions.add_subparsers(title='session subcommands', dest='session_subcommand')

    # create the parser for the "ls" subcommand
    parser_attach = subparsers.add_parser('attach', help='Attach to a session')
    parser_attach.add_argument('session_id',  help='ID of the session to attach to')
    parser_attach.add_argument('--readonly', '-r', action='store_true', help='Watch session only, no input is allowed')

    # create the parser for the "kill" subcommand
    parser_kill = subparsers.add_parser('kill', help='Kill a session')
    parser_kill.add_argument('session_id', help='ID of the session to kill')

    ## Upload CLI options
    # Upload is handled specially because the arguments (e.g., multiple file paths) is a little different
    #subparser_session = subparsers.add_parser("session", help="Query currently active SSH connections")

    #subparser_session.add_argument("-r", "--repo_uid", help="Unique ID of repo to upload to", required=True, type=str)

    #subparser_upload.add_argument("filepath", help="path of file(s) to upload", nargs='+',
    #                              type=str)

    args = parser.parse_args()

    # create logger
    logger = logging.getLogger('sshbouncer_client')
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

    if args.command == 'sessions':
        client = MQClient()
        client.make_request(SessionListRequestDto())

        response = client.listen_for_response()
        if response is None:
            logger.error("Unable to communicate with sshbouncerd")
            sys.exit(1)

        list_data = response.dto_payload  # type: SessionListResponseDto
        print("SESSIONS")
        print(list_data)
        if args.json:
            logger.info(list_data.to_json())
        else:
            out_table = PrettyTable()
            out_table.set_style(SINGLE_BORDER)
            fields = ['User', 'Last Activity', 'Session Start', 'Client IP', 'TTY']

            out_table.field_names = fields
            for session in list_data.sessions:
                row = [session.username, session.last_activity_time, session.start_time,
                               f'{session.client_ip}:{session.client_port}', session.tty_id]
                out_table.add_row(row)

            logger.info("\n" + out_table.get_string(sortby='User'))




