import threading
import queue
import zmq
from .dtos import RequestMessage, ResponseMessage, deserialize_message
from .dtos import SESSION_LIST_REQUEST, EVENT_WATCH_REQUEST, SHELL_SENDKEYS_REQUEST
from .request_handlers import ListSessionHandler, WatchHandler
from trackers.tracker import Tracker
from .active_streams import ActiveStreams
import logging
import os
import fcntl
import termios
from signal import SIGWINCH
from .mq_base import _bind_zmq_socket, NAMED_PIPE_REQ_PATH, NAMED_PIPE_RESP_PATH

logger = logging.getLogger('sshbouncer_daemon')

class MQRequestThread(threading.Thread):
    def __init__(self, message_callback, zmq_socket, is_alive_function,
                 group=None, target=None, name=None, args=(), kwargs=None):

        super(MQRequestThread,self).__init__(group=group, target=target,
                              name=name)

        self.message_callback = message_callback
        self.zmq_socket = zmq_socket
        self.is_alive_function = is_alive_function


    def run(self):

        while self.is_alive_function():
            try:

                # Check for request messages
                try:
                    message = self.zmq_socket.recv()
                    request_message = deserialize_message(message.decode('utf-8'))

                    if request_message is not None:
                        logger.debug("Request message: " + str(request_message))
                        self.message_callback(request_message)

                except zmq.error.Again:
                    # Timeout expired
                    pass

            except:
                logger.exception("Error encountered processing request.  Continuing.")


class MQResponseThread(threading.Thread):
    def __init__(self, response_queue, zmq_socket, is_alive_function,
                 group=None, target=None, name=None, args=(), kwargs=None):
        super(MQResponseThread,self).__init__(group=group, target=target,
                              name=name)
        self.response_queue = response_queue
        self.zmq_socket = zmq_socket
        self.is_alive_function = is_alive_function


    def run(self):

        while self.is_alive_function():
            try:

                # Send any response messages that have arrived on the queue
                try:
                    response_message = self.response_queue.get(timeout=0.1)  # type: ResponseMessage
                    print(f"SENDING RESPONSE {response_message}")
                    self.zmq_socket.send_string(f"{response_message.client_id} {response_message.to_json()}")
                    self.response_queue.task_done()
                except queue.Empty:
                    pass
            except:
                logger.exception("Error encountered processing request.  Continuing.")

class MQLocalServer(threading.Thread):
    '''
    Acts as a server to receive requests from client process (sshbouncer)
    responds with data that client can display to CLI
    '''
    def __init__(self, session_tracker: Tracker):

        self.session_tracker = session_tracker
        self.response_queue = queue.Queue()
        self.active_streams = ActiveStreams()
        self._stay_alive = True


    def start(self):

        # Setup the sockets
        self.context = zmq.Context()

        self.req_socket = self.context.socket(zmq.PULL)
        _bind_zmq_socket(self.req_socket, NAMED_PIPE_REQ_PATH)
        self.req_socket.setsockopt(zmq.RCVTIMEO, 100)

        self.resp_socket = self.context.socket(zmq.PUB)
        _bind_zmq_socket(self.resp_socket, NAMED_PIPE_RESP_PATH)

        # Kick off the threads
        self.request_thread = MQRequestThread(self._launch_task, self.req_socket, self.stay_alive)
        self.request_thread.start()
        self.response_thread = MQResponseThread(self.response_queue, self.resp_socket, self.stay_alive)
        self.response_thread.start()



    def _launch_task(self, request_message: RequestMessage):
        if request_message.dto_payload.payload_type == SESSION_LIST_REQUEST:
            logger.debug("Launching List Session task")
            lsh = ListSessionHandler(request_message, self.session_tracker,
                                     self.response_queue, self.stay_alive)
            lsh.start()

        elif request_message.dto_payload.payload_type == EVENT_WATCH_REQUEST:
            if self.active_streams.is_active(request_message.correlation_id):
                # Treat this as a "refresh" no need to launch a new thread
                self.active_streams.refresh(request_message.correlation_id)
            else:
                logger.debug("Launching Watch Handler task")
                self.active_streams.refresh(request_message.correlation_id)
                wh = WatchHandler(request_message, self.active_streams,
                                  self.response_queue, self.stay_alive)
                wh.start()

        elif request_message.dto_payload.payload_type == SHELL_SENDKEYS_REQUEST:
            # Client is pushing keys to apply to console.  Write them directly to TTY
            ptm_pid = request_message.dto_payload.ptm_pid
            session = self.session_tracker.get_session(ptm_pid)
            if session is None:
                logger.error(f"Cannot find session to send key for PTM PID {ptm_pid}")
                return
            tty_id = session['tty_id']
            if tty_id < 0:
                logger.error(f"Invalid TTY ID ({tty_id}) for send key PTM PID {ptm_pid}")
                return

            # When the process first connects, we need to redraw the terminal screen.
            # We send SIGWINCH to trick the terminal into thinking the window size has changed
            # and force a redraw, giving newly connected clients a cleanly redrawn terminal screen
            if request_message.dto_payload.force_redraw:
                logger.debug("Redrawing shell via SIGWINCH")
                os.kill(session['shell_pid'], SIGWINCH)

            # Write the text char-by-char to the TTY output using ioctl
            with open(f'/dev/pts/{tty_id}', 'w') as tty_out:
                for key in request_message.dto_payload.keys:
                    fcntl.ioctl(tty_out, termios.TIOCSTI, key.encode('utf-8'))



    def shutdown(self):
        self._stay_alive = False
        self.request_thread.join(timeout=1.0)
        self.response_thread.join(timeout=1.0)

    def stay_alive(self):
        return self._stay_alive


    # def run(self):
    #     context = zmq.Context()
    #
    #     req_socket = context.socket(zmq.PULL)
    #     _bind_zmq_socket(req_socket, NAMED_PIPE_REQ_PATH)
    #     req_socket.setsockopt(zmq.RCVTIMEO, 100)
    #
    #     resp_socket = context.socket(zmq.PUB)
    #     _bind_zmq_socket(resp_socket, NAMED_PIPE_RESP_PATH)
    #
    #     #socket.setsockopt(zmq.USE_FD, 0)
    #
    #     while self.stay_alive():
    #         try:
    #
    #             # Check for request messages
    #             try:
    #                 message = req_socket.recv()
    #                 request_message = deserialize_message(message.decode('utf-8'))
    #
    #                 if request_message is not None:
    #                     logger.debug("Request message: " + str(request_message))
    #                     self._launch_task(request_message)
    #             except zmq.error.Again:
    #                 # Timeout expired
    #                 pass
    #
    #             # Send any response messages that have arrived on the queue
    #             try:
    #                 response_message = self.response_queue.get(timeout=0.1)  # type: ResponseMessage
    #                 print(f"SENDING RESPONSE {response_message}")
    #                 resp_socket.send_string(f"{response_message.client_id} {response_message.to_json()}")
    #                 self.response_queue.task_done()
    #             except queue.Empty:
    #                 pass
    #         except:
    #             logger.exception("Error encountered processing request.  Continuing.")
