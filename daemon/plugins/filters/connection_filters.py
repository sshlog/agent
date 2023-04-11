from plugins.common.plugin import FilterPlugin
from comms.event_types import *
import time

class ignore_existing_logins_filter(FilterPlugin):

    def triggers(self):
        return [SSHTRACE_EVENT_NEW_CONNECTION, SSHTRACE_EVENT_ESTABLISHED_CONNECTION]

    def filter(self, event_data):
        # Filter connection established events that started more than 10 seconds ago
        # These are not new connections, they are events that are triggered when the daemon is restarted
        # Whenver daemon is restarted, it sends a connection established event for all existing connections

        if self.filter_arg == False:
            # Skip the filter, since they mean to disable it
            return True

        MAX_SECONDS_AGO = 10.0
        MILLISECONDS_IN_A_SEC = 1000.0
        start_time_ago = time.time() - (event_data['start_time'] / MILLISECONDS_IN_A_SEC)
        if start_time_ago > MAX_SECONDS_AGO:
            return False

        return True

class require_tty_filter(FilterPlugin):

    def triggers(self):
        return [SSHTRACE_EVENT_ESTABLISHED_CONNECTION, SSHTRACE_EVENT_CLOSE_CONNECTION, SSHTRACE_EVENT_COMMAND_START,
                SSHTRACE_EVENT_COMMAND_END, SSHTRACE_EVENT_TERMINAL_UPDATE, SSHTRACE_EVENT_FILE_UPLOAD]

    def filter(self, event_data):
        if self.filter_arg == False:
            # Skip the filter, since they mean to disable it
            return True

        if event_data['tty_id'] < 0:
            return False

        return True

class username_filter(FilterPlugin):

    def triggers(self):
        return [SSHTRACE_EVENT_ESTABLISHED_CONNECTION, SSHTRACE_EVENT_CLOSE_CONNECTION, SSHTRACE_EVENT_COMMAND_START,
                SSHTRACE_EVENT_COMMAND_END, SSHTRACE_EVENT_TERMINAL_UPDATE, SSHTRACE_EVENT_FILE_UPLOAD]

    def filter(self, event_data):
        user = self.filter_arg

        if isinstance(user, list):
            return event_data['username'] in user
        elif user != '*' and user != '' and user is not None:
            if user != event_data['username']:
                return False

        return True

class username_regex_filter(username_filter):
    def filter(self, event_data):
        user_regex = self.filter_arg
        return self._compare_regex_strings(user_regex, event_data['username'])