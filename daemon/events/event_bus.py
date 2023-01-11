from blinker import signal
from comms.event_types import *

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


def eventbus_sshtrace_push(event_data):
    event_type = event_data['event_type']
    sshtrace_event_signals[event_type].send(event_data)
