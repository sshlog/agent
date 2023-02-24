import importlib
import inspect
import os
import logging
from .plugin import EventPlugin, FilterPlugin, ActionPlugin

logger = logging.getLogger('sshlog_daemon')


def search_plugins(directories):
    '''
    Searches directories for Plugin python files.  It considers any class that subclasses
    EventPlugin or ActionPlugin.  The configurable parameters (i.e., what is put into the yaml)
    are discovered based on the function parameters to init_event or init_action functions.  If a function
    param is given a default value, then it is considered optional
    :param directories:
    :return: List of plugins and objects that are ready to be instantiated
    '''
    plugins = {}

    for directory in directories:
        if not os.path.isdir(directory):
            logger.warning(f"Plugin directory {directory} does not exist.  Skipping.")
            continue

        for filename in os.listdir(directory):
            if filename.endswith('.py') and not filename.startswith('_'):
                module_path = os.path.join(directory, filename)
                spec = importlib.util.spec_from_file_location(filename[:-3], module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj):

                        param_list = []

                        if issubclass(obj, FilterPlugin) and obj is not FilterPlugin:
                            plugin_type = 'filter_plugin'
                            param_list.append({
                                'name': 'filter_arg',
                                'required': True
                            })
                        elif issubclass(obj, ActionPlugin) and obj is not ActionPlugin:
                            plugin_type = 'action_plugin'
                            configurable_params = inspect.signature(obj.init_action).parameters

                            for param in configurable_params.values():
                                if param.name == 'self' or param.name == 'event_data':
                                    continue
                                has_default = param.default is not inspect.Parameter.empty
                                param_list.append({
                                    'name': param.name,
                                    'required': not has_default
                                })

                        else:
                            continue


                        plugins[name] = {'name': name,
                                         'type': plugin_type,
                                         'fields': param_list,
                                         'class_obj': obj}

    return plugins