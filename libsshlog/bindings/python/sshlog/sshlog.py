import ctypes
import importlib
# orjson (if available) is significantly faster
# ujson is pretty fast and more common
# std library json is relatively slow
if importlib.util.find_spec("orjson") is not None:
    import orjson as json
elif importlib.util.find_spec("ujson") is not None:
    import ujson as json
else:
    import json

# Load the C library
lib = ctypes.CDLL('libsshlog.so.1')

class SSHBOUNCER(ctypes.Structure):
    pass

# Define the sshlog_options and SSHBOUNCER structs
class sshlog_options(ctypes.Structure):
    _fields_ = [("log_level", ctypes.c_int)]

# Define the argument and return types for the sshlog_init function
lib.sshlog_init.argtypes = [ctypes.POINTER(sshlog_options)]
lib.sshlog_init.restype = ctypes.POINTER(SSHBOUNCER)

# Define the argument and return types for the sshlog_get_default_options function
lib.sshlog_get_default_options.argtypes = []
lib.sshlog_get_default_options.restype = sshlog_options

# Define args for is_ok() function
lib.sshlog_is_ok.argtypes = [ctypes.POINTER(SSHBOUNCER)]

# Define the argument and return types for the sshlog_event_poll function
lib.sshlog_event_poll.argtypes = [ctypes.POINTER(SSHBOUNCER), ctypes.c_int]
lib.sshlog_event_poll.restype = ctypes.c_void_p

# Define the argument types for the sshlog_event_release function
lib.sshlog_event_release.argtypes = [ctypes.c_void_p]

# Define the argument types for the sshlog_release function
lib.sshlog_release.argtypes = [ctypes.POINTER(SSHBOUNCER)]



class SSHLog(object):
    def __init__(self, loglevel=0):
        self.loglevel = loglevel

    def __enter__(self):
        # Call the sshlog_init function
        #print("INITIALIZING SSHB")
        options = lib.sshlog_get_default_options()
        options.log_level = self.loglevel
        self._instance = lib.sshlog_init(options)
        return self

    def __exit__(self, *args):
        #print("Destroying SSHB")
        lib.sshlog_release(self._instance)
        
    def is_ok(self):
        return lib.sshlog_is_ok(self._instance) == 0

    def poll(self, timeout_ms=100):
        # Call the sshlog_event_poll function
        if not self.is_ok():
            return None

        ptr = lib.sshlog_event_poll(self._instance, timeout_ms)
        event_data = ctypes.cast(ptr, ctypes.c_char_p).value
        if event_data is not None:
            resp = json.loads(event_data.decode('utf-8'))
            #print(json.dumps(resp))
            lib.sshlog_event_release(ctypes.c_void_p(ptr))
            return resp
        
        return None
