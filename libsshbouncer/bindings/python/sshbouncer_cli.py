from sshbouncer import SSHBouncer

with SSHBouncer(loglevel=0) as sshb:
    try:
        while sshb.is_ok():
            event_data = sshb.poll(timeout=100)
            print(event_data)
    except KeyboardInterrupt:
        pass

