from plugins.common.plugin import ActionPlugin
import logging
from logging.handlers import RotatingFileHandler
import json
import os
from comms.event_types import *

class eventlogfile_action(ActionPlugin):

    def init_action(self, log_file_path, output_json=False, max_size_mb=20, number_of_log_files=2):
        self.log_file_path = log_file_path
        self.output_json = output_json
        self.max_size_mb = max_size_mb
        self.number_of_log_files = number_of_log_files
        self.logger.info(f"Initialized action {self.name} with log file path {log_file_path}")

        # Ensure directory exists for log file
        dirpath = os.path.dirname(log_file_path)
        if not os.path.isdir(dirpath):
            os.makedirs(dirpath)

        self.file_logger = logging.getLogger(f'{self.name} logger')
        handler = RotatingFileHandler(self.log_file_path, maxBytes=self.max_size_mb*1024, backupCount=self.number_of_log_files)
        formatter = logging.Formatter('%(asctime)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        self.file_logger.addHandler(handler)
        self.file_logger.setLevel(logging.DEBUG)


    def _client_ip_str(self, event_data):
        return f"{event_data['tcp_info']['client_ip']}:{event_data['tcp_info']['client_port']}"

    def shutdown_action(self):
        pass

    def execute(self, event_data):

        if self.output_json:
            self.file_logger.info(json.dumps(event_data))
        else:
            # Reformat each item into a log-friendly format

            str_format = f"{event_data['event_type']}: ({event_data['ptm_pid']}) "

            if event_data['event_type'] == SSHTRACE_EVENT_NEW_CONNECTION:
                str_format += f" from ip {self._client_ip_str(event_data)}"
            elif event_data['event_type'] == SSHTRACE_EVENT_ESTABLISHED_CONNECTION:
                str_format += f"{event_data['username']} from ip {self._client_ip_str(event_data)}"
            elif event_data['event_type'] == SSHTRACE_EVENT_CLOSE_CONNECTION:
                str_format += f"{event_data['username']} from ip {self._client_ip_str(event_data)}"
            elif event_data['event_type'] == SSHTRACE_EVENT_COMMAND_START:
                str_format += f"{event_data['username']} executed {event_data['args']}"
            elif event_data['event_type'] == SSHTRACE_EVENT_COMMAND_END:
                str_format += f"{event_data['username']} execute complete (exit code: {event_data['exit_code']}) {event_data['args']}"
            elif event_data['event_type'] == SSHTRACE_EVENT_FILE_UPLOAD:
                str_format += f"{event_data['username']} uploaded file {event_data['target_path']}"
            elif event_data['event_type'] == SSHTRACE_EVENT_TERMINAL_UPDATE:
                str_format += f"{event_data['username']} terminal update ({event_data['data_len']} bytes)"

            self.file_logger.info(str_format)


        