# Copyright 2026- by CHMOD 700 LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (AGPLv3)

from plugins.common.plugin import ActionPlugin
import smtplib
from email.mime.text import MIMEText

class email_action(ActionPlugin):

    def init_action(self, sender, recipient, subject, smtp_server, smtp_port, body='', username=None, password=None):
        self.sender = sender
        self.recipient = recipient
        self.subject = subject
        self.body = body
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.logger.info(f"Initialized action {self.name} with email recipient {recipient}")

    def shutdown_action(self):
        pass

    def execute(self, event_data):
        self.logger.info(f"{self.name} Email action triggered on {event_data['event_type']} Sending to {self.recipient}")
        message = MIMEText(self._insert_event_data(event_data, self.body))
        message['Subject'] = self._insert_event_data(event_data, self.subject)
        message['From'] = self.sender
        message['To'] = self.recipient

        smtp_server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        smtp_server.ehlo()
        smtp_server.starttls()
        if self.username is not None and self.password is not None:
            smtp_server.login(self.username, self.password)
        smtp_server.sendmail(self.sender, self.recipient, message.as_string())
        smtp_server.quit()
