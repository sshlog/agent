# Copyright 2026- by CHMOD 700 LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (AGPLv3)

from dataclasses import dataclass
import dataclasses
from dataclasses_json import dataclass_json
from typing import List, Dict, Any
import json
from uuid import uuid4

SESSION_LIST_REQUEST = 1
SESSION_LIST_RESPONSE = 2

EVENT_WATCH_REQUEST = 101
EVENT_WATCH_RESPONSE = 102

SHELL_SENDKEYS_REQUEST = 201

KILL_SESSION_REQUEST = 301
KILL_SESSION_RESPONSE = 302

class SerializableMessage:
    def __init__(self, dto_payload):
        self.payload_type = dto_payload.payload_type

    def __str__(self):
        return f"client_id: {self.client_id} correlation_id: {self.correlation_id} - {self.dto_payload.__repr__()}"
    def to_json(self):
        json_obj = json.dumps({
            'client_id': self.client_id,
            'correlation_id': self.correlation_id,
            'payload_type': self.payload_type,
            'dto_payload': self.dto_payload.to_json()
        })
        return json_obj


class RequestMessage(SerializableMessage):
    def __init__(self, dto_payload, client_id, correlation_id=None):
        super(RequestMessage, self).__init__(dto_payload)
        self.client_id = client_id
        if not correlation_id:
            self.correlation_id = uuid4().__str__()
        else:
            self.correlation_id = correlation_id
        self.dto_payload = dto_payload

class ResponseMessage(SerializableMessage):
    def __init__(self, dto_payload, client_id, correlation_id):
        super(ResponseMessage, self).__init__(dto_payload)
        self.client_id = client_id
        self.correlation_id = correlation_id
        self.dto_payload = dto_payload



@dataclass_json
@dataclass(frozen=True)
class SessionListRequestDto:
    payload_type: int = SESSION_LIST_REQUEST


@dataclass_json
@dataclass(frozen=True)
class EventWatchRequestDto:
    event_types: List[str]
    ptm_pid: int = -1
    payload_type: int = EVENT_WATCH_REQUEST


@dataclass_json
@dataclass(frozen=True)
class ShellSendKeysRequestDto:
    ptm_pid: int
    keys: str
    force_redraw: bool = False
    payload_type: int = SHELL_SENDKEYS_REQUEST


@dataclass_json
@dataclass(frozen=True)
class KillSessionRequestDto:
    ptm_pid: int
    payload_type: int = KILL_SESSION_REQUEST


@dataclass_json
@dataclass(frozen=True)
class EventWatchResponseDto:
    event_type: str
    payload_json: Dict[str, Any]
    payload_type: int = EVENT_WATCH_RESPONSE


@dataclass_json
@dataclass(frozen=True)
class KillSessionResponseDto:
    success: bool
    payload_type: int = KILL_SESSION_RESPONSE


@dataclass_json
@dataclass(frozen=True)
class SessionDto:
    ptm_pid: int
    pts_pid: int
    shell_pid: int
    tty_id: int
    start_time: int
    end_time: int
    last_activity_time: int
    last_command: str
    user_id: int
    username: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int


@dataclass_json
@dataclass(frozen=True)
class SessionListResponseDto:
    sessions: List[SessionDto]
    payload_type: int = SESSION_LIST_RESPONSE


def deserialize_message(json_data):
    raw_dict = json.loads(json_data)
    if raw_dict['payload_type'] == SESSION_LIST_REQUEST:
        return RequestMessage(SessionListRequestDto.from_json(raw_dict['dto_payload']), client_id=raw_dict['client_id'], correlation_id=raw_dict['correlation_id'])
    elif raw_dict['payload_type'] == SESSION_LIST_RESPONSE:
        return ResponseMessage(SessionListResponseDto.from_json(raw_dict['dto_payload']), client_id=raw_dict['client_id'], correlation_id=raw_dict['correlation_id'])
    elif raw_dict['payload_type'] == EVENT_WATCH_REQUEST:
        return ResponseMessage(EventWatchRequestDto.from_json(raw_dict['dto_payload']), client_id=raw_dict['client_id'], correlation_id=raw_dict['correlation_id'])
    elif raw_dict['payload_type'] == EVENT_WATCH_RESPONSE:
        return ResponseMessage(EventWatchResponseDto.from_json(raw_dict['dto_payload']), client_id=raw_dict['client_id'], correlation_id=raw_dict['correlation_id'])
    elif raw_dict['payload_type'] == SHELL_SENDKEYS_REQUEST:
        return ResponseMessage(ShellSendKeysRequestDto.from_json(raw_dict['dto_payload']), client_id=raw_dict['client_id'], correlation_id=raw_dict['correlation_id'])
    elif raw_dict['payload_type'] == KILL_SESSION_REQUEST:
        return ResponseMessage(KillSessionRequestDto.from_json(raw_dict['dto_payload']), client_id=raw_dict['client_id'], correlation_id=raw_dict['correlation_id'])
    elif raw_dict['payload_type'] == KILL_SESSION_RESPONSE:
        return ResponseMessage(KillSessionResponseDto.from_json(raw_dict['dto_payload']), client_id=raw_dict['client_id'], correlation_id=raw_dict['correlation_id'])
    else:
        raise NotImplementedError(f"Could not deserialize message type for JSON {json_data}")



# test_list = []
# for i in range(0, 2):
#     test_list.append(TestListDto(item1="hi", item2=2))
#
#
# # support both positional and keyword args
# request = RequestDto(SessionListRequestDto(
#     name="Old Rod",
#     location=1.0,
#     description="Fish for low-level Pokemon",
#     test_list=test_list
# ))
#
# json_rep = request.to_json()
# print(json_rep)
#
# print("RT")
# request_rt = from_json(json_rep)
# print(request_rt)
#
#
# response = ResponseDto(SessionListResponseDto(
#     name="Who"
# ), request_rt.correlation_id)
#
# json_rep = response.to_json()
# print(json_rep)
# print("RT")
# request_rt = from_json(json_rep)
# print(request_rt)