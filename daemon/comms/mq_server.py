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
from .mq_base import _bind_zmq_socket, NAMED_PIPE_REQ_PATH

logger = logging.getLogger('sshlog_daemon')

BACKEND_PROC_ID = 'inproc://backend'
CONTROL_PROC_ID = 'inproc://proxy_control'
class MQRequestHandlerThread(threading.Thread):
    def __init__(self, message_callback, response_queue, zmq_context, is_alive_function,
                 group=None, target=None, name=None, args=(), kwargs=None):

        super(MQRequestHandlerThread,self).__init__(group=group, target=target,
                              name=name)

        self.message_callback = message_callback
        self.response_queue = response_queue
        self.zmq_context = zmq_context
        self.zmq_socket = self.zmq_context.socket(zmq.DEALER)
        self.zmq_socket.setsockopt(zmq.RCVTIMEO, 100)
        self.zmq_socket.connect(BACKEND_PROC_ID)
        self.is_alive_function = is_alive_function


    def run(self):

        while self.is_alive_function():
            try:

                # Check for request messages
                try:

                    ident, message = self.zmq_socket.recv_multipart()
                    request_message = deserialize_message(message.decode('utf-8'))

                    if request_message is not None:
                        logger.debug("Request message: " + str(request_message))
                        self.message_callback(request_message)

                except zmq.error.Again:
                    # Timeout expired
                    pass

                # Push all ready responses on the queue before checking for more requests
                try:
                    while self.is_alive_function() and not self.response_queue.empty():
                        response_message = self.response_queue.get(timeout=0.1)  # type: ResponseMessage
                        self.zmq_socket.send_multipart([response_message.client_id.encode('ascii'), response_message.to_json().encode('utf-8')])
                        self.response_queue.task_done()
                except queue.Empty:
                    pass

            except:
                logger.exception("Error encountered processing request.  Continuing.")



class MQLocalServer(threading.Thread):
    '''
    Acts as a server to receive requests from client process (sshlog)
    responds with data that client can display to CLI
    '''
    def __init__(self, session_tracker: Tracker,
                 group=None, target=None, name=None, args=(), kwargs=None):

        super(MQLocalServer,self).__init__(group=group, target=target,
                              name=name)

        self.session_tracker = session_tracker
        self.response_queue = queue.Queue()
        self.active_streams = ActiveStreams()
        self._stay_alive = True



    def run(self):

        # Setup the sockets, one server, multiple clients
        # Pattern documented here: https://zguide.zeromq.org/docs/chapter3/#The-Asynchronous-Client-Server-Pattern
        self.context = zmq.Context()

        self.zmq_router = self.context.socket(zmq.ROUTER)
        _bind_zmq_socket(self.zmq_router, NAMED_PIPE_REQ_PATH)

        self.zmq_dealer = self.context.socket(zmq.DEALER)
        self.zmq_dealer.setsockopt(zmq.RCVTIMEO, 100)
        self.zmq_dealer.bind(BACKEND_PROC_ID)

        # The ZMQ Proxy cannot be stopped without a special Control socket
        # sending a "TERMINATE" signal on the socket allows the proxy to exit gracefully
        self.zmq_proxy_control_pull = self.context.socket(zmq.PULL)
        self.zmq_proxy_control_pull.bind(CONTROL_PROC_ID)

        self.zmq_proxy_control_push = self.context.socket(zmq.PUSH)
        self.zmq_proxy_control_push.connect(CONTROL_PROC_ID)

        # Kick off the threads
        self.request_handler_thread = MQRequestHandlerThread(self._launch_task, self.response_queue, self.context, self.stay_alive)
        self.request_handler_thread.start()

        # Thread hangs here until terminate
        zmq.proxy_steerable(self.zmq_router, self.zmq_dealer, None, self.zmq_proxy_control_pull)


        self.zmq_router.close()
        self.zmq_dealer.close()
        self.zmq_proxy_control_push.close()
        self.zmq_proxy_control_pull.close()

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
        self.request_handler_thread.join(timeout=1.0)
        self.zmq_proxy_control_push.send_string('TERMINATE')

    def stay_alive(self):
        return self._stay_alive


