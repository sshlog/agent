from plugins.common.plugin import FilterPlugin
from comms.event_types import SSHTRACE_EVENT_COMMAND_START, SSHTRACE_EVENT_COMMAND_END


class command_name_filter(FilterPlugin):

    def triggers(self):
        return [SSHTRACE_EVENT_COMMAND_START, SSHTRACE_EVENT_COMMAND_END]

    def filter(self, event_data):
        command_to_match = self.filter_arg

        if isinstance(command_to_match, list):
            return event_data['filename'] in command_to_match

        if event_data['filename'] != command_to_match:
            return False

        return True


class command_name_regex_filter(command_name_filter):

    def filter(self, event_data):
        command_to_match_regex = self.filter_arg
        return self._compare_regex_strings(command_to_match_regex, event_data['filename'])


class command_exit_code_filter(FilterPlugin):

    def triggers(self):
        return [SSHTRACE_EVENT_COMMAND_END]

    def filter(self, event_data):
        exit_code_eval_string = self.filter_arg

        if isinstance(exit_code_eval_string, list):
            return event_data['exit_code'] in exit_code_eval_string
        # Handle strings such as != 0, > 1, etc.
        return self._compare_numbers(exit_code_eval_string, event_data['exit_code'])


class command_output_contains_filter(FilterPlugin):

    def triggers(self):
        return [SSHTRACE_EVENT_COMMAND_END]

    def filter(self, event_data):
        output_to_find = self.filter_arg
        if output_to_find not in event_data['stdout']:
            return False

        return True


class command_output_contains_regex_filter(command_output_contains_filter):

    def filter(self, event_data):
        output_to_find_regex = self.filter_arg
        return self._compare_regex_strings(output_to_find_regex, event_data['stdout'])