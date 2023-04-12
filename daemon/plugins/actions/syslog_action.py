# Copyright 2023- by Open Kilt LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the Redis Source Available License 2.0 (RSALv2)

from plugins.common.plugin import ActionPlugin
import json
import pysyslogclient
from events.log_formatter import LogFormatter


class syslog_action(ActionPlugin):

    def init_action(self, server_address, port=514, program_name='sshlog', udp=True, output_json=False,
                    facility=pysyslogclient.FAC_SYSTEM, severity=pysyslogclient.SEV_INFO):

        self.output_json = output_json
        self.facility = facility
        self.severity = severity
        self.program_name = program_name
        self.event_formatter = LogFormatter()

        if udp:
            proto = "UDP"
        else:
            proto = "TCP"

        self.client = pysyslogclient.SyslogClientRFC5424(server_address, port, proto=proto)

        self.logger.info(f"Initialized action {self.name} with server {server_address}:{port}")

    def shutdown_action(self):
        pass

    def execute(self, event_data):

        if self.output_json:
            message_content = json.dumps(event_data)
        else:
            # Reformat each item into a log-friendly format

            message_content = self.event_formatter.format(event_data)


        self.client.log(message_content,
                   facility=self.facility,
                   severity=self.severity,
                   program=self.program_name,
                   pid=event_data['ptm_pid'])

        self.logger.debug(f"Syslog action triggered")



