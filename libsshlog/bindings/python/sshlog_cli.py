from sshlog import SSHLog

with SSHLog(loglevel=0) as sshb:
    try:
        while sshb.is_ok():
            event_data = sshb.poll(timeout=100)
            print(event_data)
    except KeyboardInterrupt:
        pass


# sshlogd and sshlog
# client (sshlog) Communicate with daemon via unix PIPE/socket locked down to group (e.g., sshlog) and root
# REST API
# Commands:
# - List sessions
# - Attach to session (TTY ID) (read-only)
# - Attach to session (read/write)
# - Kill session
# - Watch Commands
# - 

# Daemon features
# - pluggable modules
# - monitoring
#   - If a particular command executes
#   - If a particular command returns a status code of X
#   - If a particular user or group logs in
#   - A user has SCP'd a file
#   - If anyone logs in
#   - If someone goes SUDO
#   - Watch terminal output for string/regex
#   - Watch command output for string/regex
#   - Modification of files or files in a particular directory
#   - 
# - alarms
#    - Publish to a Slack channel
#    - Send an e-mail
#    - Send a webhook (HTTP/HTTPS) req
#    - Push to statsd
# - streams
#    - Push login/logout/commands/terminal output to syslog
#    - Push login/logout/commands/terminal output to AWS logs
#    - ''' to log files (e.g., {user-date.log})

# Server features
# - MFA once a day (e.g., click here to go to server to authenticate)
# - Key deployment and rotation
# - Remote share terminal
# - Temporary user authorization (i.e., give this person access for 2 hours)
# - Record commands/terminal output for searching/download later
# - User creation/management



# STRETCH TODO:
# - detect file transfers (SCP)
  # - Missing these sessions completely now -- no username
# - detect tunneling






# COMMS:
# - want to be easy transition from client to future server
# - Local:
# - Create two queues (send/receieve)
#   - /var/run/sshlog.sock - owned by group sshlog:  srw-rw---- 1 root sshlog