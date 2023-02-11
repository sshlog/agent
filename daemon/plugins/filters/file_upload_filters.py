import os.path

from plugins.common.plugin import FilterPlugin
from comms.event_types import SSHTRACE_EVENT_FILE_UPLOAD


class upload_file_path_filter(FilterPlugin):

    def triggers(self):
        return [SSHTRACE_EVENT_FILE_UPLOAD]

    def filter(self, event_data):
        expected_path = self.filter_arg
        target_path = event_data['target_path']
        if os.path.realpath(expected_path) != os.path.realpath(target_path):
            return False

        return True


class upload_file_path_regex_filter(upload_file_path_filter):
    def filter(self, event_data):
        expected_path_regex = self.filter_arg
        return self._compare_regex_strings(expected_path_regex, event_data['target_path'])