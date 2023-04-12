# Copyright 2023- by Open Kilt LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the Redis Source Available License 2.0 (RSALv2)

import argparse
import logging
import os
import sys
from comms.mq_client import MQClient
from comms.dtos import SessionListRequestDto, SessionListResponseDto, EventWatchRequestDto, \
    ShellSendKeysRequestDto, KillSessionRequestDto
from cli.formatter import print_sessions, print_event_structured
from cli.terminal_emulator import TerminalEmulator, TERM_QUIT_KEY
from comms.event_types import *
import json
import os
import time


def request_ptm_pid(tty_id):
    # First get the sessions list, verify that our session is listed.
    correlation_id = client.make_request(SessionListRequestDto())

    response = client.listen_for_response(correlation_id)
    if response is None:
        logger.error("Unable to communicate with sshlogd")
        sys.exit(1)
    list_data = response.dto_payload  # type: SessionListResponseDto
    ptm_id = -1
    for sess in list_data.sessions:
        if sess.tty_id == tty_id:
            ptm_id = sess.ptm_pid

    if ptm_id <= 0:
        logger.error(f"Cannot find session with TTY ID {tty_id}")
        sys.exit(1)

    return ptm_id

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="SSHLog Command Line Interface")

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

    # create the parser for the "ls" subcommand
    parser_attach = subparsers.add_parser('attach', help='Attach to a session')
    parser_attach.add_argument('tty_id',  type=int, help='TTY of the session to attach to')
    parser_attach.add_argument('--readonly', '-r', action='store_true', help='Watch session only, no input is allowed')

    # create the parser for the "kill" subcommand
    parser_kill = subparsers.add_parser('kill', help='Kill a session')
    parser_kill.add_argument('tty_id', type=int, help='TTY ID of the session to kill')

    ## Upload CLI options
    # Upload is handled specially because the arguments (e.g., multiple file paths) is a little different
    #subparser_session = subparsers.add_parser("session", help="Query currently active SSH connections")

    #subparser_session.add_argument("-r", "--repo_uid", help="Unique ID of repo to upload to", required=True, type=str)

    #subparser_upload.add_argument("filepath", help="path of file(s) to upload", nargs='+',
    #                              type=str)

    args = parser.parse_args()

    # create logger
    logger = logging.getLogger('sshlog_client')
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

    client = MQClient()
    if not client.initialized:
        sys.exit(1)

    if args.command == 'sessions':
        correlation_id = client.make_request(SessionListRequestDto())

        response = client.listen_for_response(correlation_id)
        if response is None:
            logger.error("Unable to communicate with sshlogd")
            sys.exit(1)

        list_data = response.dto_payload  # type: SessionListResponseDto
        print_sessions(list_data, output_json=args.json)

    elif args.command == 'kill':

        # First get the sessions list, verify that our session is listed.
        ptm_id = request_ptm_pid(args.tty_id)

        correlation_id = client.make_request(KillSessionRequestDto(ptm_pid=ptm_id))
        response = client.listen_for_response(correlation_id)

        if response is None:
            logger.error("Unable to communicate with sshlogd")
            sys.exit(1)

        response_data = response.dto_payload  # type: KillSessionResponseDto

        if response_data.success:
            print(f"Successfully terminated SSH session TTY {args.tty_id} (pid: {ptm_id})")
        else:
            print("Error terminating SSH session TTY {args.tty_id} (pid: {ptm_id})")



    elif args.command == 'watch':

        watch_events = [
            SSHTRACE_EVENT_ESTABLISHED_CONNECTION,
            SSHTRACE_EVENT_CLOSE_CONNECTION,
            SSHTRACE_EVENT_COMMAND_START,
            SSHTRACE_EVENT_COMMAND_END,
            SSHTRACE_EVENT_FILE_UPLOAD
        ]
        request_dto = EventWatchRequestDto(event_types=watch_events)
        request_correlation_id = client.make_request(request_dto)

        try:

            while True:
                # Continually make the watch request to keep it refreshed.
                # Once timed out, it will stop sending responses
                client.make_request(request_dto, correlation_id=request_correlation_id)

                response_data = client.listen_for_response(request_correlation_id, timeout_sec=0.25)
                if response_data is not None:
                    event_data = response_data.dto_payload.payload_json
                    print_event_structured(event_data, args.json)


        except KeyboardInterrupt:
            pass

    elif args.command == 'attach':

        # First get the sessions list, verify that our session is listed.
        ptm_id = request_ptm_pid(args.tty_id)

        # Sanity check, make sure they're not trying to attach to their own ssh session
        # This doesn't currently handle cases where user has sudo'd or is ssh'd inside and ssh session
        TTY_SYMLINK = '/proc/self/fd/0'
        if os.path.exists(TTY_SYMLINK):
            tty_id = os.path.basename(os.path.realpath(TTY_SYMLINK))
            if str(args.tty_id) == tty_id:
                logger.error(f"You are attempting to attach to your own SSH session.  Exiting.")
                sys.exit(1)

        request_dto = EventWatchRequestDto(
            event_types=[SSHTRACE_EVENT_CLOSE_CONNECTION, SSHTRACE_EVENT_TERMINAL_UPDATE],
            ptm_pid=ptm_id
        )
        request_correlation_id = client.make_request(request_dto)

        term_active = True

        def keyboard_intercept(keys):
            global term_active
            if keys == TERM_QUIT_KEY:
                term_active = False
            elif not args.readonly:
                # Push an event to the daemon so that it can WRITE to this active terminal
                shell_send_dto = ShellSendKeysRequestDto(ptm_pid=ptm_id,
                                                         keys=keys.decode('utf-8'))
                client.make_request(shell_send_dto)
            #print(f"KEY: {str(keys)}")


        os.system("tput reset")

        term = TerminalEmulator(args.tty_id)
        term.intercept_keyboard(keyboard_intercept)

        # When we first connect, send a force_redraw message so that the initial
        # bash state gets re-sent.  Otherwise, users will have to press "enter" to get an initial prompt
        client.make_request(ShellSendKeysRequestDto(ptm_pid=ptm_id,
                                                 force_redraw=True,
                                                 keys=''))

        read_only_text = ''
        if args.readonly:
            read_only_text = " in READ-ONLY mode"
        logger.info(f"Attached to TTY {args.tty_id}{read_only_text}.  Press CTRL+Q to exit\n\r")

        last_refresh_time = time.time()
        REFRESH_INTERVAL_SEC = 0.25
        while term_active:
            if time.time() - last_refresh_time > REFRESH_INTERVAL_SEC:
                # Continually make the watch request to keep it refreshed.
                # If this isn't sent regularly, it will time out and server will stop sending responses
                client.make_request(request_dto, correlation_id=request_correlation_id)
                last_refresh_time = time.time()

            response_data = client.listen_for_response(request_correlation_id, timeout_sec=0.25)

            if response_data is not None:
                event_data = response_data.dto_payload.payload_json

                # If the connection closes for this ptm, exit
                if event_data['event_type'] == SSHTRACE_EVENT_CLOSE_CONNECTION:
                    break
                elif event_data['event_type'] == SSHTRACE_EVENT_TERMINAL_UPDATE:
                    term.update(event_data['terminal_data'], event_data['data_len'])

        logger.info(f"\n\rDisconnected from TTY {args.tty_id}\r")

        term.shutdown()
    client.disconnect()
