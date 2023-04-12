# Copyright 2023- by Open Kilt LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the Redis Source Available License 2.0 (RSALv2)

import yaml
import os
import logging
from .plugin_factory import search_plugins
from .plugin import EventPlugin
from comms.event_types import SSHTRACE_ALL_EVENTS

logger = logging.getLogger('sshlog_daemon')

class PluginManager:
    def __init__(self, yaml_configs, session_tracker, user_plugin_dirs=[]):

        SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
        plugin_dirs = [
            os.path.realpath(os.path.join(SCRIPT_DIR, '../filters/')),
            os.path.realpath(os.path.join(SCRIPT_DIR, '../actions/')),
        ]
        plugin_dirs.extend(user_plugin_dirs)

        self._plugins = search_plugins(plugin_dirs)
        for plugin_name, plugin in self._plugins.items():
            logger.info(f"Detected Plugin {plugin_name} with fields {plugin['fields']}")

        self.validation_errors = []
        self.events = []
        self.actions = []
        self.session_tracker = session_tracker

        self.streams = []
        self.destinations = []

        for cfg in yaml_configs:
            logger.info(f"Reading config file {cfg}")
            if not os.path.exists(cfg):
                logger.warning(f"Configuration file {cfg} does not exist.  Skipping")
                continue

            with open(cfg, 'r') as in_file:
                try:
                    self._parse_yaml(in_file.read())
                except yaml.YAMLError as e:
                    self.validation_errors.append(f"YAML error in config file {cfg} {e}")
                except:
                    self.validation_errors.append(f"YAML unexpected error in config file {cfg}")
                    logger.exception(f"Unexpected error parsing config file: {cfg}")


        self._validate_config()

    def _parse_yaml(self, yaml_string):

        yaml_dict = yaml.load(yaml_string, Loader=yaml.FullLoader)
        events = yaml_dict.get('events', [])
        actions = yaml_dict.get('actions', [])
        for action in actions:
            self.actions.append(action)


        for event in events:

            triggers = event.get('triggers', [])
            if len(triggers) == 0:
                self.validation_errors.append(f"At least one trigger is required for event {event['event']}")

            for trigger in triggers:
                if trigger not in SSHTRACE_ALL_EVENTS:
                    self.validation_errors(f"Invalid trigger {trigger} possible triggers are {SSHTRACE_ALL_EVENTS}")

            for filter_name, filter_arg in event.get('filters', {}).items():
                filter_class_name = filter_name + '_filter'
                if filter_class_name not in self._plugins:
                    self.validation_errors.append(f"Missing filter plugin {filter_class_name} referenced by action {event['event']}")
                    continue

                event['filters'][filter_name] = {
                    'filter_name': filter_name,
                    'filter_arg': filter_arg,
                    'filter_class_name': filter_class_name,
                    'class_obj': self._plugins[filter_class_name]['class_obj']
                }


            self.events.append(event)

            for action in event.get('actions', []):
                if 'plugin' in action:
                    self.actions.append(action)


        # Attach class_obj for the plugin to each action
        for i in range(0, len(self.actions)):
            # Find the plugin name by reference
            plugin_name = self.actions[i]['plugin']
            if plugin_name not in self._plugins:
                # If we didn't find the plugin, add a validation error
                self.validation_errors.append(f"Missing plugin {plugin_name} referenced by action {self.actions[i]['action']}")
                continue

            logger.debug("CLASS OBJ: " + str(self.actions[i]))
            self.actions[i]['class_obj'] = self._plugins[plugin_name]['class_obj']

    def plugins_ok(self):
        return len(self.validation_errors) == 0


    def _validate_config(self):
        # check that there are no duplicate actions

        action_set = {}
        for action in self.actions:
            action_name = action['action']
            if action_name not in action_set:
                action_set[action_name] = True
            else:
                self.validation_errors.append(f"Duplicate action name {action_name}")

        # check that there are no duplicate events
        event_set = {}
        for event in self.events:
            event_name = event['event']
            if event_name not in event_set:
                event_set[event_name] = True
            else:
                self.validation_errors.append(f"Duplicate event name {event_name}")

        # Check that each event has a properly defined action

        for event in self.events:
            for action in event['actions']:
                action_name = action['action']
                if action_name not in action_set:
                    self.validation_errors.append(f"Missing action definition for {action_name} from event {event['event']}")


        # TODO: Check the arguments for each event/action to make sure that they match the plugin functions
        #       Check that all non-default values are specified.  Warn if any unexpected values are included

    def _clean_args(self, dict_obj, fields_to_clear: list):
        args_only = dict_obj.copy()
        for fields_to_clear in fields_to_clear:
            if fields_to_clear in args_only:
                del args_only[fields_to_clear]
        return args_only

    def initialize_plugins(self):

        self._event_objects = []

        # Create a dictionary for the actions, to make lookup easier
        action_set = {}
        for action in self.actions:
            action_name = action['action']
            if action_name not in action_set:
                action_set[action_name] = action

        # Iterate through each event
        for event in self.events:
            logger.info(f"Initializing event plugin {event['event']}")

            # Initialize the filters since they need to be passed to the new event obj
            filters_obj_list = []
            for filter_name, filter in event.get('filters', {}).items():
                logger.info(f"Initializing filter plugin {filter['filter_name']}")

                filter_object = filter['class_obj'](filter['filter_arg'], self.session_tracker)
                filters_obj_list.append(filter_object)

            # First initialize the actions, since they need to be passed to the new event plugin
            action_obj_list = []
            for action in event['actions']:
                logger.info(f"Initializing action plugin {action['action']}")
                action_name = action['action']
                default_vals = action_set[action_name]

                # Merge the two dicts together, overriding any default values with the more specific ones specified in the event config
                merged_dict = default_vals.copy()
                merged_dict.update(action)
                action = merged_dict

                # Send ONLY the arguments needed by the "init_action" function
                # Remove known non-function arguments from the dictionary and pass that through
                args_only = self._clean_args(action, ['action', 'plugin', 'class_obj'])

                action_object = action['class_obj'](action['action'], self.session_tracker, **args_only)
                action_obj_list.append(action_object)


            # Initialize the event object, passing the user-defined arguments as kwargs
            event_object = EventPlugin(event['event'], event['triggers'], filters_obj_list, action_obj_list)
            self._event_objects.append(event_object)

        # for event_plugin_name, event_plugin in self.events.items():
        #     object = event_plugin['class_obj']()
        #     object.detect('eventdata', **{'user': 'mhill2', 'require_tty': False})

    def shutdown(self):
        for ev_object in self._event_objects:
            ev_object.shutdown()
