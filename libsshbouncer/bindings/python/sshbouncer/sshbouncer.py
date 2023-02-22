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
lib = ctypes.CDLL('libsshbouncer.so.1')

class SSHBOUNCER(ctypes.Structure):
    pass

# Define the sshbouncer_options and SSHBOUNCER structs
class sshbouncer_options(ctypes.Structure):
    _fields_ = [("log_level", ctypes.c_int)]

# Define the argument and return types for the sshbouncer_init function
lib.sshbouncer_init.argtypes = [ctypes.POINTER(sshbouncer_options)]
lib.sshbouncer_init.restype = ctypes.POINTER(SSHBOUNCER)

# Define the argument and return types for the sshbouncer_get_default_options function
lib.sshbouncer_get_default_options.argtypes = []
lib.sshbouncer_get_default_options.restype = sshbouncer_options

# Define args for is_ok() function
lib.sshbouncer_is_ok.argtypes = [ctypes.POINTER(SSHBOUNCER)]

# Define the argument and return types for the sshbouncer_event_poll function
lib.sshbouncer_event_poll.argtypes = [ctypes.POINTER(SSHBOUNCER), ctypes.c_int]
lib.sshbouncer_event_poll.restype = ctypes.c_void_p

# Define the argument types for the sshbouncer_event_release function
lib.sshbouncer_event_release.argtypes = [ctypes.c_void_p]

# Define the argument types for the sshbouncer_release function
lib.sshbouncer_release.argtypes = [ctypes.POINTER(SSHBOUNCER)]



class SSHBouncer(object):
    def __init__(self, loglevel=0):
        self.loglevel = loglevel

    def __enter__(self):
        # Call the sshbouncer_init function
        #print("INITIALIZING SSHB")
        options = lib.sshbouncer_get_default_options()
        options.log_level = self.loglevel
        self._instance = lib.sshbouncer_init(options)
        return self

    def __exit__(self, *args):
        #print("Destroying SSHB")
        lib.sshbouncer_release(self._instance)
        
    def is_ok(self):
        return lib.sshbouncer_is_ok(self._instance) == 0

    def poll(self, timeout_ms=100):
        # Call the sshbouncer_event_poll function
        if not self.is_ok():
            return None

        ptr = lib.sshbouncer_event_poll(self._instance, timeout_ms)
        event_data = ctypes.cast(ptr, ctypes.c_char_p).value
        if event_data is not None:
            resp = json.loads(event_data.decode('utf-8'))
            #print(json.dumps(resp))
            lib.sshbouncer_event_release(ctypes.c_void_p(ptr))
            return resp
        
        return None
