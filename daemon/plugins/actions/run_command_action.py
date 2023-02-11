from plugins.common.plugin import ActionPlugin
import subprocess

class run_command_action(ActionPlugin):

    def init_action(self, command, args=[]):
        self.command = command
        self.args = args
        self.logger.info(f"Initialized action {self.name} with command {command}")

    def shutdown_action(self):
        pass

    def execute(self, event_data):
        args_list = [self.command]
        for arg in self.args:
            # Swap out any {{value}} items in the arguments list
            args_list.append(self._insert_event_data(event_data, arg))
        args_list.extend(self.args)

        self.logger.debug(f"Executing command f{args_list}")
        subprocess.call(args_list)