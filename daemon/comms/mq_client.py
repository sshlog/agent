import zmq
from .dtos import RequestMessage, deserialize_message
import time
import logging
from uuid import uuid4
from .mq_base import NAMED_PIPE_REQ_PATH
import os

logger = logging.getLogger('sshlog_client')

class MQClient:
    def __init__(self):
        # Generate a pseudo-random "client id" for each MQClient
        self.client_id = uuid4().__str__()
        self.initialized = False


        if not os.path.exists(NAMED_PIPE_REQ_PATH) or not os.access(NAMED_PIPE_REQ_PATH, os.R_OK):
            logger.warning(f"Permission denied accessing SSHLog daemon socket: unix://{NAMED_PIPE_REQ_PATH}\n"
                           f"To use sshlog, you must either be a member of the 'sshlog' group, or the root user")
            return

        self.context = zmq.Context()
        self.zmq_socket = self.context.socket(zmq.DEALER)
        self.zmq_socket.setsockopt(zmq.RCVTIMEO, 100)
        self.zmq_socket.setsockopt(zmq.LINGER, 0)
        self.zmq_socket.identity = self.client_id.encode('ascii')
        self.zmq_socket.connect(f"ipc://{NAMED_PIPE_REQ_PATH}")


        self.initialized = True

    def make_request(self, dto_payload, correlation_id=None):
        msg = RequestMessage(dto_payload, self.client_id, correlation_id)
        correlation_id = msg.correlation_id
        raw_data = msg.to_json()
        logger.debug(f"Request: {raw_data}")
        resp = self.zmq_socket.send(raw_data.encode('utf-8'))
        logger.debug(f"response {resp}")
        return correlation_id



    def listen_for_response(self, correlation_id, timeout_sec=1.0):
        start_time = time.time()

        while time.time() - start_time < timeout_sec:
            try:
                payload = self.zmq_socket.recv()

                message = deserialize_message(payload)
                if message.correlation_id == correlation_id:
                    return message

                # Message received, but it's not for this client (wrong correlation ID)
            except zmq.error.Again:
                # Timeout expired
                pass

        return None

    def disconnect(self):
        #self.resp_socket.unsubscribe(self.client_id)
        self.zmq_socket.disconnect(f"ipc://{NAMED_PIPE_REQ_PATH}")