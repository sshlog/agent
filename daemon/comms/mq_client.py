import zmq
from .dtos import RequestMessage, deserialize_message
import time
import logging
from uuid import uuid4
from .mq_base import NAMED_PIPE_REQ_PATH, NAMED_PIPE_RESP_PATH

logger = logging.getLogger('sshlog_client')

class MQClient:
    def __init__(self):
        # Generate a pseudo-random "client id" for each MQClient
        self.client_id = uuid4().__str__()
        self.initialized = False

        for pipepath in [NAMED_PIPE_REQ_PATH, NAMED_PIPE_RESP_PATH]:
            try:
                with open(pipepath, 'r') as inf:
                    pass
            except PermissionError:
                logger.warning(f"Permission denied accessing SSHLog daemon socket: unix://{pipepath}\n"
                               f"To use sshlog, you must either be a member of the 'sshlog' group, or the root user")
                return

        self.context = zmq.Context()
        self.req_socket = self.context.socket(zmq.PUSH)
        self.req_socket.connect(f"ipc://{NAMED_PIPE_REQ_PATH}")

        self.resp_socket = self.context.socket(zmq.SUB)
        self.resp_socket.connect(f"ipc://{NAMED_PIPE_RESP_PATH}")

        # Set the timeout for receiving messages to 100 milliseconds
        self.resp_socket.setsockopt(zmq.RCVTIMEO, 100)
        #self.resp_socket.setsockopt(zmq.SUBSCRIBE, self.client_id.encode('utf-8'))
        self.resp_socket.subscribe(self.client_id)

        self.initialized = True

    def make_request(self, dto_payload, correlation_id=None):
        msg = RequestMessage(dto_payload, self.client_id, correlation_id)
        correlation_id = msg.correlation_id
        raw_data = msg.to_json()
        logger.debug(f"Request: {raw_data}")
        resp = self.req_socket.send(raw_data.encode('utf-8'))
        logger.debug(f"response {resp}")
        return correlation_id



    def listen_for_response(self, correlation_id, timeout_sec=1.0):
        start_time = time.time()

        while time.time() - start_time < timeout_sec:
            try:
                raw_msg = self.resp_socket.recv().decode('utf-8')
                # Topic (aka client ID) will be the first string separated by space.  Split just the first item and
                # send the rest for deserializing
                topic, payload = raw_msg.split(" ", 1)
                message = deserialize_message(payload)
                if message.correlation_id == correlation_id:
                    return message

                # Message received, but it's not for this client (wrong correlation ID)
            except zmq.error.Again:
                # Timeout expired
                # print("Timeout expired while waiting for a message")
                pass

        return None

    def disconnect(self):
        self.resp_socket.unsubscribe(self.client_id)
        self.resp_socket.disconnect(f"ipc://{NAMED_PIPE_RESP_PATH}")
        self.req_socket.disconnect(f"ipc://{NAMED_PIPE_REQ_PATH}")