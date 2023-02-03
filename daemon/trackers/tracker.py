from events.event_bus import eventbus_sshtrace_subscribe
from comms.event_types import *
import time

class Tracker:

    def __init__(self):
        self.connections = {}
        self.commands = {}

        eventbus_sshtrace_subscribe(self.connection_open, SSHTRACE_EVENT_NEW_CONNECTION)
        eventbus_sshtrace_subscribe(self.connection_established, SSHTRACE_EVENT_ESTABLISHED_CONNECTION)
        eventbus_sshtrace_subscribe(self.connection_closed, SSHTRACE_EVENT_CLOSE_CONNECTION)

        eventbus_sshtrace_subscribe(self.command_activity, SSHTRACE_EVENT_COMMAND_START)
        eventbus_sshtrace_subscribe(self.connection_activity, SSHTRACE_EVENT_TERMINAL_UPDATE)

    def connection_open(self, event_data):
        pid_key = event_data['ptm_pid']
        self.connections[pid_key] = event_data

    def connection_established(self, event_data):
        pid_key = event_data['ptm_pid']
        self.connections[pid_key] = event_data
        self.connections[pid_key]['last_activity_time'] = round(time.time() * 1000.0)
        self.connections[pid_key]['last_command'] = ''

    def connection_closed(self, event_data):
        pid_key = event_data['ptm_pid']
        if pid_key in self.connections:
            del self.connections[pid_key]

    def connection_activity(self, event_data):
        pid_key = event_data['ptm_pid']
        if pid_key in self.connections:
            self.connections[pid_key]['last_activity_time'] = round(time.time() * 1000.0)

    def command_activity(self, event_data):
        pid_key = event_data['ptm_pid']
        if pid_key in self.connections:
            self.connections[pid_key]['last_command'] = event_data['args']



    def get_sessions(self):
        return self.connections.values()

    def get_session(self, session_pid):
        if session_pid in self.connections:
            return self.connections[session_pid]
        return None

    def get_commands(self):
        self.commands.values()


