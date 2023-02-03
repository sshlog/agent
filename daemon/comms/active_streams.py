import time

class ActiveStreams:
    def __init__(self):
        self.MAX_SECONDS = 1.0
        self.active_streams = {}

    def refresh(self, correlation_id):
        # TODO: this dictionary will grow forever, it's likely very small amount of RAM
        #       but should consider pruning the list every so often for very old entries
        self.active_streams[correlation_id] = time.time()

    def is_active(self, correlation_id):
        if correlation_id not in self.active_streams:
            return False

        seconds_since_refresh = time.time() - self.active_streams[correlation_id]
        #print(f"SECONDS: {seconds_since_refresh}")
        return seconds_since_refresh <= self.MAX_SECONDS
