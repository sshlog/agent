# Copyright 2023- by Open Kilt LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the Redis Source Available License 2.0 (RSALv2)


from comms.event_types import *

class LogFormatter:
    def __init__(self):
        self.event_type_padding = self._max_string_length(SSHTRACE_ALL_EVENTS)


    def _max_string_length(self, arr):
        max_length = 0
        for element in arr:
            if len(element) > max_length:
                max_length = len(element)
        return max_length

    def _client_ip_str(self, event_data):
        return f"{event_data['tcp_info']['client_ip']}:{event_data['tcp_info']['client_port']}"

    def format(self, event_data):

        str_format = f"{event_data['event_type']:{self.event_type_padding}} ({event_data['ptm_pid']}) "

        # If username field is empty we don't want to add an extra space
        if 'username' not in event_data or event_data['username'] == '':
            username_padded = ''
        else:
            username_padded = event_data['username'] + ' '

        if event_data['event_type'] == SSHTRACE_EVENT_NEW_CONNECTION:
            str_format += f"from ip {self._client_ip_str(event_data)}"
        elif event_data['event_type'] == SSHTRACE_EVENT_ESTABLISHED_CONNECTION:
            str_format += f"{username_padded}from ip {self._client_ip_str(event_data)} tty {event_data['tty_id']}"
        elif event_data['event_type'] == SSHTRACE_EVENT_AUTH_FAILED_CONNECTION:
            str_format += f"{username_padded}from ip {self._client_ip_str(event_data)}"
        elif event_data['event_type'] == SSHTRACE_EVENT_CLOSE_CONNECTION:
            str_format += f"{username_padded}from ip {self._client_ip_str(event_data)}"
        elif event_data['event_type'] == SSHTRACE_EVENT_COMMAND_START:
            str_format += f"{username_padded}from ip {self._client_ip_str(event_data)} executed {event_data['args']}"
        elif event_data['event_type'] == SSHTRACE_EVENT_COMMAND_END:
            str_format += f"{username_padded}from ip {self._client_ip_str(event_data)} execute complete (exit code: {event_data['exit_code']}) {event_data['args']}"
        elif event_data['event_type'] == SSHTRACE_EVENT_FILE_UPLOAD:
            str_format += f"{username_padded}from ip {self._client_ip_str(event_data)} uploaded file {event_data['target_path']}"
        elif event_data['event_type'] == SSHTRACE_EVENT_TERMINAL_UPDATE:
            str_format += f"{username_padded}terminal update ({event_data['data_len']} bytes)"

        return str_format