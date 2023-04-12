# Copyright 2023- by Open Kilt LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the Redis Source Available License 2.0 (RSALv2)

import threading
from trackers.tracker import Tracker
import queue
from .dtos import SessionListResponseDto, SessionDto, EventWatchResponseDto, ResponseMessage, \
    RequestMessage, KillSessionResponseDto
from events.event_bus import eventbus_sshtrace_subscribe, eventbus_sshtrace_unsubscribe
from comms.event_types import *
import os
import signal
import time
import logging

logger = logging.getLogger('sshlog_daemon')

class RequestHandler(threading.Thread):
    '''
    Parent class for handling incoming CLI requests off the MQ.  Spawns a separate thread,
    does the work, then pushes response data (with correct correlation ID) back to the client
    '''
    def __init__(self, client_id: str, correlation_id: str, response_queue: queue.Queue,
                 stay_alive_func,
                 group=None, target=None, name=None, args=(), kwargs=None):
        super(RequestHandler, self).__init__(group=group, target=target,
                                       name=name)
        self.client_id = client_id
        self.correlation_id = correlation_id
        self.response_queue = response_queue
        self.stay_alive_func = stay_alive_func

    def return_data(self, response_dto):
        response_message = ResponseMessage(response_dto, self.client_id, self.correlation_id)
        if self.stay_alive_func():
            self.response_queue.put(response_message)


class ListSessionHandler(RequestHandler):

    def __init__(self, request_message: RequestMessage, session_tracker: Tracker, response_queue: queue.Queue,
                 stay_alive_func,
                group=None, target=None, name=None, args=(), kwargs=None):
        super(ListSessionHandler, self).__init__(request_message.client_id, request_message.correlation_id,
                                                 response_queue, stay_alive_func,
                                                 group=group, target=target, name=name)
        self.session_tracker = session_tracker

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
                last_command=session['last_command'],
                user_id=session['user_id'],
                username=session['username'],
                client_ip=session['tcp_info']['client_ip'],
                client_port=session['tcp_info']['client_port'],
                server_ip=session['tcp_info']['server_ip'],
                server_port=session['tcp_info']['server_port']
            ))
        resp_dto = SessionListResponseDto(sessions=all_sessions)

        self.return_data(resp_dto)


class KillSessionHandler(RequestHandler):

    def __init__(self, request_message: RequestMessage, response_queue: queue.Queue,
                 stay_alive_func,
                group=None, target=None, name=None, args=(), kwargs=None):
        self.ptm_pid = request_message.dto_payload.ptm_pid
        super(KillSessionHandler, self).__init__(request_message.client_id, request_message.correlation_id,
                                                 response_queue, stay_alive_func,
                                                 group=group, target=target, name=name)

    def run(self):

        # check if process exists
        if os.path.exists(f"/proc/{self.ptm_pid}"):
            # terminate the process
            os.kill(self.ptm_pid, signal.SIGTERM)
            success = True
        else:
            success = False

        resp_dto = KillSessionResponseDto(success=success)

        self.return_data(resp_dto)

class WatchHandler(RequestHandler):

    def __init__(self, request_message: RequestMessage,
                 active_streams, response_queue: queue.Queue, stay_alive_func,
                group=None, target=None, name=None, args=(), kwargs=None):
        super(WatchHandler, self).__init__(request_message.client_id, request_message.correlation_id,
                                           response_queue, stay_alive_func,
                                                 group=group, target=target, name=name)
        self.active_streams = active_streams
        self.event_types = request_message.dto_payload.event_types
        self.ptm_pid = request_message.dto_payload.ptm_pid

    def event_received(self, event_data):
        # if they've applied a filter on PTM PID, make sure we match
        if self.ptm_pid > 0 and event_data['ptm_pid'] != self.ptm_pid:
            return

        resp_dto = EventWatchResponseDto(event_type=event_data['event_type'],
                                         payload_json=event_data)
        self.return_data(resp_dto)

    def run(self):

        logger.debug("Event watch subscribing")
        eventbus_sshtrace_subscribe(self.event_received, self.event_types)

        while self.active_streams.is_active(self.correlation_id) and self.stay_alive_func():
            time.sleep(0.1)

        logger.debug("Event watch unsubscribing")
        eventbus_sshtrace_unsubscribe(self.event_received, self.event_types)
