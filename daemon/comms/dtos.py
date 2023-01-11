from dataclasses import dataclass
import dataclasses
from dataclasses_json import dataclass_json
from typing import List
import json
from uuid import uuid4

SESSION_LIST_REQUEST = 1
SESSION_LIST_RESPONSE = 2

class SerializableMessage:
    def __init__(self, dto_payload):
        self.payload_type = dto_payload.payload_type

    def __str__(self):
        return self.correlation_id + " - " + self.dto_payload.__repr__()
    def to_json(self):
        json_obj = json.dumps({
            'correlation_id': self.correlation_id,
            'payload_type': self.payload_type,
            'dto_payload': self.dto_payload.to_json()
        })
        return json_obj


class RequestMessage(SerializableMessage):
    def __init__(self, dto_payload, correlation_id=None):
        super(RequestMessage, self).__init__(dto_payload)
        if not correlation_id:
            self.correlation_id = uuid4().__str__()
        else:
            self.correlation_id = correlation_id
        self.dto_payload = dto_payload

class ResponseMessage(SerializableMessage):
    def __init__(self, dto_payload, correlation_id):
        super(ResponseMessage, self).__init__(dto_payload)
        self.correlation_id = correlation_id
        self.dto_payload = dto_payload



@dataclass_json
@dataclass(frozen=True)
class SessionListRequestDto:
    payload_type: int = SESSION_LIST_REQUEST

@dataclass_json
@dataclass(frozen=True)
class SessionDto:
    ptm_pid: int
    pts_pid: int
    shell_pid: int
    tty_id: int
    start_time: str
    end_time: str
    last_activity_time: int
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
        return RequestMessage(SessionListRequestDto.from_json(raw_dict['dto_payload']), correlation_id=raw_dict['correlation_id'])
    elif raw_dict['payload_type'] == SESSION_LIST_RESPONSE:
        return ResponseMessage(SessionListResponseDto.from_json(raw_dict['dto_payload']), correlation_id=raw_dict['correlation_id'])



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