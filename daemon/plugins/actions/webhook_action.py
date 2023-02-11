from plugins.common.plugin import ActionPlugin
import requests
import urllib.parse

class webhook_action(ActionPlugin):

    def init_action(self, webhook_url, do_get_request=False):
        self.webhook_url = webhook_url
        self.do_get_request = do_get_request
        self.logger.info(f"Initialized action {self.name} with url {webhook_url}")

    def shutdown_action(self):
        pass

    def execute(self, event_data):
        if self.do_get_request:
            # Structure a get request payload
            query_args = urllib.parse.urlencode(event_data)
            url = self.webhook_url + '?' + query_args
            response = requests.get(url)

        else:
            url = self.webhook_url
            response = requests.post(url, data=event_data)

        if response.status_code != 200:
            self.logger.info(f"Received {response.status_code} response for webhook action {self.name}")
