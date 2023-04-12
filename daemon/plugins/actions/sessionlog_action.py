# Copyright 2023- by Open Kilt LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the Redis Source Available License 2.0 (RSALv2)

from plugins.common.plugin import ActionPlugin
from comms.event_types import *
import os
import re
import time
import datetime

key_to_text_mapping = {
    '\x01': '[Ctrl+A]',
    '\x02': '[Ctrl+B]',
    '\x03': '[Ctrl+C]',
    '\x04': '[Ctrl+D]',
    '\x05': '[Ctrl+E]',
    '\x06': '[Ctrl+F]',
    #'\x07': '[Ctrl+G]',
    '\x07': '',
    '\x08': '[←]', # Backspace/left arrow
    '\x0b': '[Ctrl+K]',
    '\x0c': '[Ctrl+L]',
    '\x0e': '[Ctrl+N]',
    '\x0f': '[Ctrl+O]',
    '\x10': '[Ctrl+P]',
    '\x11': '[Ctrl+Q]',
    '\x12': '[Ctrl+R]',
    '\x13': '[Ctrl+S]',
    '\x14': '[Ctrl+T]',
    '\x15': '[Ctrl+U]',
    '\x16': '[Ctrl+V]',
    '\x17': '[Ctrl+W]',
    '\x18': '[Ctrl+X]',
    '\x19': '[Ctrl+Y]',
    '\x1a': '[Ctrl+Z]',
    #'\x1b': '[Ctrl+[ ]',
    '\x1b': '',
    '\x1d': '[Ctrl+]]',
    '\x1f': '[Ctrl+/]',
    '\x7f': '[<--]',
    '\x5d0;': '', # Not sure what this character is, but it shows up on first line of terminal after coloring
    #'\t': '[Tab]',
    '\r': ''
   }


class sessionlog_action(ActionPlugin):

    def init_action(self, log_directory, timestamp_frequency_seconds=-1):
        self.log_directory = log_directory
        self.timestamp_frequency_seconds = timestamp_frequency_seconds
        self.logger.info(f"Initialized action {self.name} with log directory {log_directory}")
        self.ansi_escape_regex = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
        self.special_char_regex = '|'.join(re.escape(char) for char in key_to_text_mapping)

        self.last_timestamp = 0.0

        # Ensure directory exists
        if not os.path.isdir(log_directory):
            # Make the directory readable only by owner (root)
            os.makedirs(log_directory, mode=0o700)

    def shutdown_action(self):
        pass

    def _remove_coloring(self, term_data):
        return self.ansi_escape_regex.sub('', term_data)

    def _convert_special_chars(self, term_data):
        '''
        Removes escape sequences and makes output data more suitable for log files
        :return: Cleaned text
        '''

        return re.sub(self.special_char_regex, lambda m: key_to_text_mapping[m.group(0)], term_data)


    def write_data(self, output_path, content):

        with open(output_path, 'a') as log_out:
            log_out.write(content)

    def execute(self, event_data):
        filename = f"ssh_{event_data['ptm_pid']}.log"
        output_path = os.path.join(self.log_directory, filename)

        if event_data['event_type'] == SSHTRACE_EVENT_TERMINAL_UPDATE:

            #connection_data = self.session_tracker.get_session(event_data['ptm_pid'])
            if self.timestamp_frequency_seconds > 0 and time.time() - self.last_timestamp > self.timestamp_frequency_seconds:
                self.last_timestamp = time.time()
                # Output date string always in UTC
                date_string = datetime.datetime.utcnow().isoformat() + "Z"
                content = f"\n[[ sshlog time: {date_string} ]]\n"
                self.write_data(output_path, content)

            filename = f"ssh_{event_data['ptm_pid']}.log"
            output_path = os.path.join(self.log_directory, filename)

            terminal_data = event_data['terminal_data']
            decolored_terminal_data = self._remove_coloring(terminal_data)
            cleaned_terminal_data = self._convert_special_chars(decolored_terminal_data)
            # for key, value in key_to_text_mapping.items():
            #     if key in terminal_data:
            #         terminal_data = terminal_data.replace(key, value)

            if not os.path.isdir(self.log_directory):
                os.makedirs(self.log_directory)

            with open(output_path, 'a') as log_out:
                log_out.write(cleaned_terminal_data)

            # Intermediate outputs for debugging
            # with open(output_path + '.orig', 'a') as log_out:
            #     log_out.write(terminal_data)
            # with open(output_path + '.mid', 'a') as log_out:
            #     log_out.write(decolored_terminal_data)

        elif event_data['event_type'] == SSHTRACE_EVENT_CLOSE_CONNECTION:
            end_time_iso_8601 = datetime.datetime.utcfromtimestamp(event_data['end_time'] / 1000.0).isoformat() + 'Z'
            content = f"\n[[ sshlog {event_data['event_type']} user: {event_data['username']} at {end_time_iso_8601} ]]\n"
            self.write_data(output_path, content)

        elif event_data['event_type'] == SSHTRACE_EVENT_ESTABLISHED_CONNECTION:
            start_time_iso_8601 = datetime.datetime.utcfromtimestamp(event_data['start_time'] / 1000.0).isoformat() + 'Z'
            content = f"\n[[ sshlog {event_data['event_type']} user: {event_data['username']} at {start_time_iso_8601} ]]\n"
            self.write_data(output_path, content)
