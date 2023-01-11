import threading
from trackers.tracker import Tracker
import queue
from .dtos import SessionListResponseDto, SessionDto, ResponseMessage


class RequestHandler(threading.Thread):
    '''
    Parent class for handling incoming CLI requests off the MQ.  Spawns a separate thread,
    does the work, then pushes response data (with correct correlation ID) back to the client
    '''
    def __init__(self, correlation_id: str, session_tracker: Tracker, response_queue: queue.Queue,
                 stay_alive_func,
                 group=None, target=None, name=None, args=(), kwargs=None):
        super(RequestHandler, self).__init__(group=group, target=target,
                                       name=name)
        self.session_tracker = session_tracker
        self.correlation_id = correlation_id
        self.response_queue = response_queue
        self.stay_alive_func = stay_alive_func

    def return_data(self, response_dto):
        response_message = ResponseMessage(response_dto, self.correlation_id)
        if self.stay_alive_func():
            self.response_queue.put(response_message)


class ListSessionHandler(RequestHandler):

    def __init__(self, correlation_id: str, session_tracker: Tracker, response_queue: queue.Queue,
                 stay_alive_func,
                group=None, target=None, name=None, args=(), kwargs=None):
        super(ListSessionHandler, self).__init__(correlation_id, session_tracker, response_queue,
                                                 stay_alive_func,
                                                 group=group, target=target, name=name)

    def run(self):
        all_sessions = []
        for session in self.session_tracker.get_sessions():
            all_sessions.append(SessionDto(
                ptm_pid=session['ptm_pid'],
                pts_pid=session['pts_pid'],
                shell_pid=session['shell_pid'],
                tty_id=session['tty_id'],
                start_time=session['start_time'],
                end_time=session['end_time'],
                last_activity_time=session['last_activity_time'],
                user_id=session['user_id'],
                username=session['username'],
                client_ip=session['tcp_info']['client_ip'],
                client_port=session['tcp_info']['client_port'],
                server_ip=session['tcp_info']['server_ip'],
                server_port=session['tcp_info']['server_port']
            ))
        resp_dto = SessionListResponseDto(sessions=all_sessions)

        self.return_data(resp_dto)