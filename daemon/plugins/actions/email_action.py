from plugins.common.plugin import ActionPlugin
import smtplib
from email.mime.text import MIMEText

class email_action(ActionPlugin):

    def init_action(self, sender, recipient, subject, body, smtp_server, smtp_port, username=None, password=None):
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
        message = MIMEText(self.body)
        message['Subject'] = self.subject
        message['From'] = self.sender
        message['To'] = self.recipient

        smtp_server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        smtp_server.ehlo()
        smtp_server.starttls()
        if self.username is not None and self.password is not None:
            smtp_server.login(self.username, self.password)
        smtp_server.sendmail(self.sender, self.recipient, message.as_string())
        smtp_server.quit()
