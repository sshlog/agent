# Copyright 2023- by Open Kilt LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the Redis Source Available License 2.0 (RSALv2)

from comms.dtos import SessionListResponseDto
from prettytable import PrettyTable
from prettytable import PLAIN_COLUMNS
import logging
import json
from datetime import datetime
from events.log_formatter import LogFormatter
import datetime
import timeago
import timeago.locales.en # Import this explicitly so that pyinstaller finds it

logger = logging.getLogger('sshlog_client')

def _convert_epoch_ms_to_time(epoch_ms):
    return datetime.datetime.fromtimestamp(epoch_ms/1000).strftime('%Y-%m-%d %H:%M:%S')

def _convert_epoch_ms_to_time_ago(epoch_ms):
    dt = datetime.datetime.fromtimestamp(epoch_ms/1000)
    return timeago.format(dt, datetime.datetime.now(), 'en')


def print_sessions(sessions_list: SessionListResponseDto, output_json=False):

    if output_json:
        logger.info(sessions_list.to_json())
    else:
        out_table = PrettyTable()
        out_table.set_style(PLAIN_COLUMNS)
        fields = ['User', 'Last Activity', 'Last Command', 'Session Start', 'Client IP', 'TTY']

        out_table.field_names = fields
        for session in sessions_list.sessions:
            row = [session.username, _convert_epoch_ms_to_time_ago(session.last_activity_time), session.last_command, _convert_epoch_ms_to_time(session.start_time),
                   f'{session.client_ip}:{session.client_port}', session.tty_id]
            out_table.add_row(row)

        # If there's no rows, add a dummy row so that the headers will still print
        if len(sessions_list.sessions) == 0:
            out_table.add_row([''] * len(fields))

        logger.info(out_table.get_string(sortby='User'))


def print_event_structured(event, output_json=False):
    if output_json:
        logger.info(json.dumps(event))
    else:
        event_formatter = LogFormatter()

        event_str = event_formatter.format(event)

        now = datetime.datetime.now()
        current_time = now.strftime("%H:%M:%S")

        logger.info(current_time + " " + event_str)

        # for k, v in sorted(event.items()):
        #     if k == 'event_type': # Skip event type since we've already printed it
        #         continue
        #     if k.endswith('_timeraw'):
        #         # skip the raw timestamps.  They're not human-readable
        #         continue
        #     if k == "start_time" or k == "end_time":
        #         human_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(v) / 1000))
        #         v = human_time
        #     logger.info(f"  - {k.ljust(13)}: {v}")
        # logger.info("")
