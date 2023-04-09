from plugins.common.plugin import ActionPlugin
import requests
import json
import socket
import datadog
from comms.event_types import *

class statsd_action(ActionPlugin):

    def init_action(self, server_address, port=8125, statsd_prefix='sshlog'):

        self.client = datadog.DogStatsd(
            host=server_address, port=port,
            disable_telemetry=True,
            namespace=statsd_prefix,
            constant_tags=[f"hostname:{socket.gethostname()}"]
        )

        self.logger.info(f"Initialized action {self.name} with server {server_address}:{port}")

    def shutdown_action(self):
        pass


    def execute(self, event_data):

        if event_data['event_type'] == SSHTRACE_EVENT_TERMINAL_UPDATE:
            self.logger.warning(
                "Terminal update events probably should not trigger stats.  Assuming misconfigurationand skipping")
            return

        tags = [
            f"user:{event_data['username']}",
            f"pid:{event_data['ptm_pid']}",
        ]

        # For connection types, include the client IP and prot
        if 'tcp_info' in event_data:
            tags.append(f"client_ip:{event_data['tcp_info']['client_ip']}")
            tags.append(f"client_port:{event_data['tcp_info']['client_port']}")

        # Append special tags for different data types.  Useful for filtering metrics
        if event_data['event_type'] in [SSHTRACE_EVENT_COMMAND_START, SSHTRACE_EVENT_COMMAND_END]:
            tags.append(f"command:{event_data['filename']}")
        elif event_data['event_type'] in [SSHTRACE_EVENT_FILE_UPLOAD]:
            tags.append(f"upload_file:{event_data['target_path']}")

        self.logger.debug(f"Statsd action triggered")

        self.client.increment(event_data['event_type'], 1, tags=tags)  # Increment the counter.



