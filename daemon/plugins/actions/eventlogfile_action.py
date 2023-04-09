from plugins.common.plugin import ActionPlugin
import logging
from logging.handlers import RotatingFileHandler
import json
import os
from events.log_formatter import LogFormatter

class eventlogfile_action(ActionPlugin):

    def init_action(self, log_file_path, output_json=False, max_size_mb=20, number_of_log_files=2):
        self.log_file_path = log_file_path
        self.output_json = output_json
        self.max_size_mb = max_size_mb
        self.number_of_log_files = number_of_log_files
        self.logger.info(f"Initialized action {self.name} with log file path {log_file_path}")

        self.event_formatter = LogFormatter()

        # Ensure directory exists for log file
        dirpath = os.path.dirname(log_file_path)
        if not os.path.isdir(dirpath):
            os.makedirs(dirpath)

        self.file_logger = logging.getLogger(f'{self.name} logger')
        handler = RotatingFileHandler(self.log_file_path, maxBytes=self.max_size_mb*1024*1024, backupCount=self.number_of_log_files)
        formatter = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        self.file_logger.addHandler(handler)
        self.file_logger.setLevel(logging.DEBUG)


    def shutdown_action(self):
        pass


    def execute(self, event_data):

        self.logger.debug(f"{self.name} processing event {event_data['event_type']}")
        if self.output_json:
            self.file_logger.info(json.dumps(event_data))
        else:
            # Reformat each item into a log-friendly format

            str_format = self.event_formatter.format(event_data)

            self.file_logger.info(str_format)


        