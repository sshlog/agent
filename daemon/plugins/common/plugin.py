# Copyright 2026- by CHMOD 700 LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (AGPLv3)

import logging
from trackers.tracker import Tracker
from events.event_bus import eventbus_sshtrace_subscribe, eventbus_sshtrace_unsubscribe
from comms.event_types import SSHTRACE_ALL_EVENTS
import operator
import re
import concurrent.futures
import os

# Assume most action handling is IO-bound.  Default to use 16 threads per CPU core
action_threadpool_executor = concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()*16)

class EventPlugin:
    def __init__(self, name, triggers: list, filters: list, actions: list, **kwargs):
        self.name = name
        self.triggers = triggers
        self.filters = filters
        self.actions = actions
        self.logger = logging.getLogger('sshlog_daemon')

        for trigger in self.triggers:
            if trigger not in SSHTRACE_ALL_EVENTS:
                raise RuntimeError(f"Trigger {trigger} in invalid.  Possible triggers are {SSHTRACE_ALL_EVENTS}")

        for filter in self.filters:
            # Make sure that the configured "filter" could possibly fire on the list of triggers for the events
            # e.g., it doesn't make sense to have a command filter running when only connection events are being watched
            common_elements = set(filter.triggers()).intersection(self.triggers)
            if len(common_elements) <= 0:
                raise RuntimeError(f"Filter {filter} for event {self.name} is invalid.  The filter can only execute on "
                                   f"triggers {filter.triggers()}, and the event is only configured for triggers {self.triggers}")

        eventbus_sshtrace_subscribe(self._event_callback, self.triggers)


    def shutdown(self):
        self.logger.info(f"Shutting down event plugin {self.name}")
        eventbus_sshtrace_unsubscribe(self._event_callback, self.triggers)
        for action in self.actions:
            action.shutdown()

    def _event_callback(self, event_data):
        for filter in self.filters:

            try:
                # Only pass to filters that are configured to handle this event type
                if event_data['event_type'] not in filter.triggers():
                    continue

                passes_filter = filter.filter(event_data)
                if not isinstance(passes_filter, bool):
                    self.logger.warning(f"Invalid response ({passes_filter}) from plugin {self.name} detect function.  Response must be boolean")
                    return

                if passes_filter == False:
                    self.logger.debug(f"Skipping event for {self.name} on failure due to filter {filter}")
                    return

            except:
                self.logger.exception(f"Error handling filter for plugin {self.name} on filter {filter}")

        # Event has passed all filters, trigger actions
        for action in self.actions:
            try:
                #action._execute(event_data)
                action_threadpool_executor.submit(action._execute, event_data)
            except:
                self.logger.exception(f"Error handling event for event plugin {self.name} action {action.name}")



class FilterPlugin:
    def __init__(self, filter_arg, session_tracker: Tracker, **kwargs):
        self.logger = logging.getLogger('sshlog_daemon')
        self.filter_arg = filter_arg
        self.session_tracker = session_tracker

        self._number_eval_dict = {
            '<': operator.lt,
            '<=': operator.le,
            '>': operator.gt,
            '>=': operator.ge,
            '=': operator.eq,
            '!=': operator.ne,
            #'nand': lambda x, y: not (x and y)
        }

    def __str__(self):
        return self.__class__.__name__

    def _compare_numbers(self, comparison_str: str, value):
        '''
        Allow customers to provide a comparison operator (e.g., '>= 5', '!= 0', etc) for string comparison
        :param comparison_str: The comparison value (e.g., '>= 5').  If it's just a number, assume it's an equality operation
        :param value: The actual value to compare against
        :return: True if it matches, False otherwise
        '''
        components = comparison_str.split()
        if len(components) == 1:
            # This is an equality test
            components = ['=', components[0]]
        elif len(components) > 2:
            # This is an invalid comparison
            self.logger.warning(f"Invalid comparison operation.  Cannot parse {comparison_str}")
            return False

        inequality_operator = components[0] # e.g., <, >=, etc.
        if inequality_operator not in self._number_eval_dict:
            self.logger.warning(f"Invalid comparison operation {inequality_operator} valid operations are {self._number_eval_dict.keys()}")
            return False

        if '.' in components[1]:
            user_eval_number = float(components[1])
        else:
            user_eval_number = int(components[1])

        return self._number_eval_dict[inequality_operator](user_eval_number, value)

    def _compare_regex_strings(self, string_match: str, value):
        '''
        Performs a regex string match against the value
        :param string_match: regex to search
        :param value: to search against using regex
        :return: True if it matches, false otherwise
        '''

        match = re.search(string_match, value)
        if match:
            return True
        else:
            return False


    def triggers(self):
        return SSHTRACE_ALL_EVENTS

    def filter(self, event_data):
        ''' Given a configured argument, check the event data to see if the event should be allowed to proceed
        returns True if the filter is passed (i.e., it matches the configured argument) and
                False if it does not match and the event should not propogate
        '''
        raise RuntimeError("The filter function must be implemented in the subclass for the filter plugin to function")


class ActionPlugin:
    def __init__(self, name, session_tracker: Tracker, **kwargs):
        self.name = name
        self.session_tracker = session_tracker
        self.logger = logging.getLogger('sshlog_daemon')
        self.init_action(**kwargs)

    def _insert_event_data(self, event_data, template):
        # For all dictionary items in "event_data" swap out any {{x}} values.
        # e.g., 'hello my name is {{username}}' would become: 'Hello my name is mhill'
        for k, v in event_data.items():
            replace_key = '{{' + k + '}}'
            if replace_key in template:
                template = template.replace(replace_key, str(v))
        return template

    def shutdown(self):
        self.logger.info(f"Shutting down action plugin {self.name}")
        self.shutdown_action()

    def init_action(self):
        ''' Init action to be overridden by child plugin '''
        pass

    def shutdown_action(self):
        ''' Shutdown action to be overridden by child plugin '''
        pass

    def _execute(self, event_data):
        # Wrapper to log exceptions
        try:
            self.execute(event_data)
        except:
            self.logger.exception(f"Error triggering action plugin {self.name}")
    def execute(self, event_data):
        ''' Execute action to be overridden by child plugin '''
        raise RuntimeError("The detect function must be implemented for the event to function")