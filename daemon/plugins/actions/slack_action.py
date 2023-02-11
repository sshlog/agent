from plugins.common.plugin import ActionPlugin
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


class slack_action(ActionPlugin):

    def init_action(self, slack_channel_id, slack_api_token, message='sshbouncerd event: {{event_type}}'):
        self.slack_channel_id = slack_channel_id
        self.slack_api_token = slack_api_token
        self.message = message
        self.client = WebClient(token=self.slack_api_token)
        self.logger.info(f"Initialized action {self.name} with slack channel {self.slack_channel_id}")

    def shutdown_action(self):
        pass

    def execute(self, event_data):

        try:
            response = self.client.chat_postMessage(
                channel=self.channel_id,
                text=self.message
            )
            self.logger.debug(response)
        except SlackApiError as e:
            self.logger.exception(f"{self.name} action: error sending message to Slack channel {self.slack_channel_id}")

