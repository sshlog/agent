from comms.dtos import SessionListRequestDto, SessionListResponseDto, EventWatchRequestDto
from prettytable import PrettyTable
from prettytable import PLAIN_COLUMNS, SINGLE_BORDER
import logging
import json
import time
from comms.event_types import *
import datetime
import timeago

logger = logging.getLogger('sshbouncer_client')

def _convert_epoch_ms_to_time(epoch_ms):
    return datetime.datetime.fromtimestamp(epoch_ms/1000).strftime('%Y-%m-%d %H:%M:%S')

def _convert_epoch_ms_to_time_ago(epoch_ms):
    dt = datetime.datetime.fromtimestamp(epoch_ms/1000)
    return timeago.format(dt, datetime.datetime.now())


def print_sessions(sessions_list: SessionListResponseDto, output_json=False):
    pass


    if output_json:
        logger.info(sessions_list.to_json())
    else:
        out_table = PrettyTable()
        out_table.set_style(SINGLE_BORDER)
        fields = ['User', 'Last Activity', 'Last Command', 'Session Start', 'Client IP', 'TTY']

        out_table.field_names = fields
        for session in sessions_list.sessions:
            row = [session.username, _convert_epoch_ms_to_time_ago(session.last_activity_time), session.last_command, _convert_epoch_ms_to_time(session.start_time),
                   f'{session.client_ip}:{session.client_port}', session.tty_id]
            out_table.add_row(row)

        logger.info("\n" + out_table.get_string(sortby='User'))


def print_event_structured(event, output_json=False):
    if output_json:
        logger.info(json.dumps(event))
    else:
        #logger.info(json.dumps(event))
        event_str = ''

        if event['event_type'] == SSHTRACE_EVENT_NEW_CONNECTION or event['event_type'] == SSHTRACE_EVENT_ESTABLISHED_CONNECTION or \
                event['event_type'] == SSHTRACE_EVENT_CLOSE_CONNECTION:
            event_str = f"pid {event['ptm_pid']} {event['username']}:{event['tty_id']} {event['event_type']}"
        elif event['event_type'] == SSHTRACE_EVENT_COMMAND_END or event['event_type'] == SSHTRACE_EVENT_COMMAND_START:
            event_str = f"pid {event['ptm_pid']} {event['username']}:{event['tty_id']} {event['event_type']} {event['filename']}"
        elif event['event_type'] == SSHTRACE_EVENT_FILE_UPLOAD:
            event_str = f"pid {event['ptm_pid']} {event['username']}:{event['tty_id']} {event['event_type']} {event['target_path']}"
        else:
            event_str = f"UNKNOWN EVENT: {json.dumps(event)}"
        logger.info(event_str)

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
