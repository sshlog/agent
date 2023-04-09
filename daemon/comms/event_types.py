
# These constants are defined in libsshlog sshtrace_events.h and mapped to strings in event_serializer.cpp
SSHTRACE_EVENT_ESTABLISHED_CONNECTION = 'connection_established'
SSHTRACE_EVENT_CLOSE_CONNECTION = 'connection_close'
SSHTRACE_EVENT_AUTH_FAILED_CONNECTION = 'connection_auth_failed'
SSHTRACE_EVENT_COMMAND_START = 'command_start'
SSHTRACE_EVENT_COMMAND_END = 'command_finish'
SSHTRACE_EVENT_TERMINAL_UPDATE = 'terminal_update'
SSHTRACE_EVENT_FILE_UPLOAD = 'file_upload'

# The new connection event should never propagate to sshlog
SSHTRACE_EVENT_NEW_CONNECTION = 'connection_new'

SSHTRACE_ALL_EVENTS = [
    SSHTRACE_EVENT_ESTABLISHED_CONNECTION,
    SSHTRACE_EVENT_AUTH_FAILED_CONNECTION,
    SSHTRACE_EVENT_CLOSE_CONNECTION,
    SSHTRACE_EVENT_COMMAND_START,
    SSHTRACE_EVENT_COMMAND_END,
    SSHTRACE_EVENT_TERMINAL_UPDATE,
    SSHTRACE_EVENT_FILE_UPLOAD
]


# For reference, these are sample payloads for the various events.  This data is subject to change
# and these comments may not be updated to reflect the latest values

# {'event_type': 'connection_new', 'ptm_pid': 2782281, 'user_id': -1, 'username': '', 'pts_pid': -1, 'shell_pid': -1, 'tty_id': -1, 'start_time': 1677084819930, 'end_time': 0, 'start_timeraw': 851155551084463, 'end_timeraw': 0, 'tcp_info': {'server_ip': '0', 'client_ip': '127.0.0.1', 'server_port': 0, 'client_port': 36636}}
# {'event_type': 'connection_established', 'ptm_pid': 2782281, 'user_id': 1000, 'username': 'mhill', 'pts_pid': 2782323, 'shell_pid': 2782324, 'tty_id': -1, 'start_time': 1677084819930, 'end_time': 0, 'start_timeraw': 851155551084463, 'end_timeraw': 0, 'tcp_info': {'server_ip': '0', 'client_ip': '127.0.0.1', 'server_port': 0, 'client_port': 36636}}
# {"event_type": "connection_auth_failed", "ptm_pid":3916537,  "user_id":135,"username":"haproxy","pts_pid":-1,"shell_pid":-1,"tty_id":-1,"start_time":1677430550000,"end_time":1677430550000,"start_timeraw":1677430550000,"end_timeraw":1677430550000,"tcp_info":{"server_ip":"0","client_ip":"127.0.0.1","server_port":0,"client_port":0}}

# {'event_type': 'terminal_update', 'ptm_pid': 2768632, 'terminal_data': 'l', 'data_len': 1}
# {'event_type': 'command_start', 'ptm_pid': 2782281, 'filename': 'bash', 'start_time': 1677084820167, 'end_time': 0, 'exit_code': -1, 'stdout_size': 0, 'stdout': '', 'args': '/bin/bash -c scp -t /tmp/a.b', 'parent_pid': 2782323, 'pid': 2782324, 'username': 'mhill', 'tty_id': -1}
# {'event_type': 'command_finish', 'ptm_pid': 2782281, 'filename': 'scp', 'start_time': 1677084820168, 'end_time': 1677084820172, 'exit_code': 0, 'stdout_size': 3, 'stdout': '', 'args': '/usr/bin/scp -t /tmp/a.b', 'parent_pid': 2782323, 'pid': 2782324, 'username': 'mhill', 'tty_id': -1}

# {'event_type': 'connection_close', 'ptm_pid': 2782281, 'user_id': 1000, 'username': 'mhill', 'pts_pid': 2782323, 'shell_pid': 2782324, 'tty_id': -1, 'start_time': 1677084819930, 'end_time': 1677084820174, 'start_timeraw': 851155551084463, 'end_timeraw': 851155795227451, 'tcp_info': {'server_ip': '0', 'client_ip': '127.0.0.1', 'server_port': 0, 'client_port': 36636}}
# {'event_type': 'file_upload', 'ptm_pid': 2782281, 'target_path': '/tmp/a.b', 'file_mode': '664', 'username': 'mhill', 'tty_id': -1}