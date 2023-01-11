import threading
import queue
import zmq
from .dtos import RequestMessage, ResponseMessage, deserialize_message
from .dtos import SESSION_LIST_REQUEST
from .request_handlers import ListSessionHandler
from trackers.tracker import Tracker
import logging
import pwd
import grp
import os
from pathlib import Path

logger = logging.getLogger('sshbouncer_daemon')

class MQLocalServer(threading.Thread):
    '''
    Acts as a server to receive requests from client process (sshbouncer)
    responds with data that client can display to CLI
    '''
    def __init__(self, session_tracker: Tracker, group=None, target=None, name=None,
                 args=(), kwargs=None):
        super(MQLocalServer,self).__init__(group=group, target=target,
                              name=name)
        self.session_tracker = session_tracker
        self.response_queue = queue.Queue()
        self._stay_alive = True
        self.named_pipe_path = '/tmp/my_pipe'
        self.os_group_name = "sshbouncer"

    def _launch_task(self, request_message: RequestMessage):
        if request_message.dto_payload.payload_type == SESSION_LIST_REQUEST:
            lsh = ListSessionHandler(request_message.correlation_id, self.session_tracker,
                                     self.response_queue, self.stay_alive)
            lsh.start()

    def shutdown(self):
        self._stay_alive = False

    def stay_alive(self):
        return self._stay_alive

    def ensure_sock_file_permissions(self):
        '''
        Ensures that the socket file permission is set to root:sshbouncer 660
        :return:
        '''
        uid = pwd.getpwnam("root").pw_uid
        try:
            gid = grp.getgrnam(self.os_group_name).gr_gid
        except KeyError:
            logger.warning("MQ Server binding could not find sshbouncer user")
            gid = grp.getgrnam("root").gr_gid

        os.chown(self.named_pipe_path, uid, gid)

    def run(self):
        context = zmq.Context()
        socket = context.socket(zmq.PAIR)

        # Ensures correct permissions.  We want 660 and root/sshbouncer
        original_umask = os.umask(0o117)
        socket.bind(f"ipc://{self.named_pipe_path}")
        self.ensure_sock_file_permissions()
        os.umask(original_umask)

        socket.setsockopt(zmq.RCVTIMEO, 100)
        #socket.setsockopt(zmq.USE_FD, 0)

        while self.stay_alive():
            try:

                # Check for request messages
                try:
                    message = socket.recv()
                    request_message = deserialize_message(message.decode('utf-8'))

                    logger.debug("Request message: " + str(request_message))
                    if request_message is not None:
                        logger.debug("Launching task")
                        self._launch_task(request_message)
                except zmq.error.Again:
                    # Timeout expired
                    pass

                # Send any response messages that have arrived on the queue
                try:
                    response_message = self.response_queue.get(timeout=0.1)  # type: ResponseMessage
                    socket.send(response_message.to_json().encode())
                    self.response_queue.task_done()
                except queue.Empty:
                    pass
            except:
                logger.exception("Error encountered processing request.  Continuing.")