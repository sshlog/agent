from plugins.common.plugin import ActionPlugin
import os
from threading import Lock


key_to_text_mapping = {
    '\x01': '[Ctrl+A]',
    '\x02': '[Ctrl+B]',
    '\x03': '[Ctrl+C]',
    '\x04': '[Ctrl+D]',
    '\x05': '[Ctrl+E]',
    '\x06': '[Ctrl+F]',
    '\x07': '[Ctrl+G]',
    '\x08': '[Ctrl+H]',
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
    '\x1b': '[Ctrl+[ ]',
    '\x1d': '[Ctrl+]]',
    '\x1f': '[Ctrl+/]',
    '\x7f': '[<--]',
    '\t': '[Tab]',
    '\r': '[Enter]\r\n'
   }


class sessionlog_action(ActionPlugin):

    def init_action(self, log_directory):
        self.log_directory = log_directory
        self.logger.info(f"Initialized action {self.name} with log directory {log_directory}")


    def shutdown_action(self):
        pass

    def execute(self, event_data):
        connection_data = self.session_tracker.get_session(event_data['ptm_pid'])
        print(connection_data)

        filename = f"ssh_{connection_data['username']}_{event_data['ptm_pid']}.log"
        output_path = os.path.join(self.log_directory, filename)

        terminal_data = event_data['terminal_data']
        # for key, value in key_to_text_mapping.items():
        #     if key in terminal_data:
        #         terminal_data = terminal_data.replace(key, value)

        if not os.path.isdir(self.log_directory):
            os.makedirs(self.log_directory)

        with open(output_path, 'a') as log_out:
            log_out.write(terminal_data)