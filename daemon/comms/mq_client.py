import zmq
from .dtos import RequestMessage, deserialize_message
import time

class MQClient:
    def __init__(self):
        self.named_pipe_path = '/tmp/my_pipe'
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PAIR)
        self.socket.connect(f"ipc://{self.named_pipe_path}")
        self.correlation_id = None

        # Set the timeout for receiving messages to 1000 milliseconds
        self.socket.setsockopt(zmq.RCVTIMEO, 100)

    def make_request(self, dto_payload):
        msg = RequestMessage(dto_payload)
        self.correlation_id = msg.correlation_id
        raw_data = msg.to_json().encode()
        print(raw_data)
        resp = self.socket.send(raw_data)
        print(resp)



    def listen_for_response(self):
        start_time = time.time()

        MAX_WAIT_S = 1.00
        while time.time() - start_time < MAX_WAIT_S:
            try:
                message = deserialize_message(self.socket.recv())
                if message.correlation_id == self.correlation_id:
                    return message

                # Message received, but it's not for this client (wrong correlation ID)
            except zmq.error.Again:
                # Timeout expired
                # print("Timeout expired while waiting for a message")
                pass

        return None