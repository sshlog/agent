import os
import pwd
import grp

NAMED_PIPE_REQ_PATH = '/tmp/sshbouncerd_req.sock'
NAMED_PIPE_RESP_PATH = '/tmp/sshbouncerd_resp.sock'
OS_GROUP_NAME = "sshbouncer"


def _ensure_sock_file_permissions(named_pipe_path):
    '''
    Ensures that the socket file permission is set to root:sshbouncer 660
    :return:
    '''
    uid = pwd.getpwnam("root").pw_uid
    try:
        gid = grp.getgrnam(OS_GROUP_NAME).gr_gid
    except KeyError:
        return False
        #self.logger.warning("MQ Server binding could not find sshbouncer user")
        gid = grp.getgrnam("root").gr_gid

    os.chown(named_pipe_path, uid, gid)
    return True


def _bind_zmq_socket(pub_socket, named_pipe_path):

    # Ensures correct permissions.  We want 660 and root/sshbouncer
    original_umask = os.umask(0o117)
    pub_socket.bind(f"ipc://{named_pipe_path}")
    success = _ensure_sock_file_permissions(named_pipe_path)
    os.umask(original_umask)

    return success
