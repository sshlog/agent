from blinker import signal
from comms.event_types import *
import concurrent.futures
import os
import logging

logger = logging.getLogger('sshbouncer_daemon')


# Assume most event handling is IO-bound.  Default to use 4 threads per CPU core
# event_threadpool_executor = concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()*4)

# Use the event types from comms.event_types
sshtrace_event_signals = {}
for sshtrace_event_id in SSHTRACE_ALL_EVENTS:
    sshtrace_event_signals[sshtrace_event_id] = signal(f'sshtrace_event-{sshtrace_event_id}')


def eventbus_sshtrace_subscribe(callback, event_ids=None):
    if event_ids is None:
        event_ids = SSHTRACE_ALL_EVENTS
    elif type(event_ids) != list:
        event_ids = [event_ids]

    for event_id in event_ids:
        sshtrace_event_signals[event_id].connect(callback)


def eventbus_sshtrace_unsubscribe(callback, event_ids=None):
    if event_ids is None:
        event_ids = SSHTRACE_ALL_EVENTS
    elif type(event_ids) != list:
        event_ids = [event_ids]

    for event_id in event_ids:
        sshtrace_event_signals[event_id].disconnect(callback)


def eventbus_sshtrace_push(event_data, session_tracker):
    event_type = event_data['event_type']
    # Attach connection data to events here
    if event_type == SSHTRACE_EVENT_COMMAND_START or event_type == SSHTRACE_EVENT_COMMAND_END or \
            event_type == SSHTRACE_EVENT_FILE_UPLOAD:
        # Lookup the active connection for this PID and attach some useful information to the event
        active_conn = session_tracker.get_session(event_data['ptm_pid'])
        if active_conn is not None:
            event_data['username'] = active_conn['username']
            event_data['tty_id'] = active_conn['tty_id']
        else:
            event_data['username'] = ''
            event_data['tty_id'] = ''

    logger.debug(event_data)

    # Run on multiple threads
    #event_threadpool_executor.submit(sshtrace_event_signals[event_type].send, event_data)
    # Send events concurrently, the threading happens when actions are triggered
    sshtrace_event_signals[event_type].send(event_data)
