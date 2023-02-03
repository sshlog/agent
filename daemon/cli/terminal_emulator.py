import sys
import tty
import termios
import threading
import select

TERM_QUIT_KEY = b'\x11'  # CTRL+Q

class KeyboardInterceptThread(threading.Thread):

    def __init__(self, key_event_callback,
                 group=None, target=None, name=None, args=(), kwargs=None):
        super(KeyboardInterceptThread, self).__init__(group=group, target=target,
                                       name=name)
        self.key_event_callback = key_event_callback


    def get_keys(self):

        fd = sys.stdin.fileno()
        orig_fl = termios.tcgetattr(fd)
        try:
            #tty.setcbreak(fd)  # use tty.setraw() instead to catch ^C also
            tty.setraw(fd)
            mode = termios.tcgetattr(fd)
            CC = 6
            mode[CC][termios.VMIN] = 0
            mode[CC][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSAFLUSH, mode)

            keypress, _, _ = select.select([fd], [], [])
            if keypress:
                return sys.stdin.read(1048575)  # Big buffer to accommodate copy/paste
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, orig_fl)

        return None


    def run(self):

        #self.term_settings = termios.tcgetattr(sys.stdin)

        while True:
            keys = self.get_keys()
            if keys is None or len(keys) == 0:
                continue
            utf8_keys = keys.encode('utf-8')
            #desired_array = [ord(char) for char in keys]
            #print(desired_array)
            self.key_event_callback(utf8_keys)

            if utf8_keys == TERM_QUIT_KEY:
                break

        #termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.term_settings)

class TerminalEmulator:
    def __init__(self, tty_id):
        self.tty_id = tty_id

    def update(self, bytes, num_bytes):

        sys.stdout.write(bytes)
        sys.stdout.flush()


    def intercept_keyboard(self, key_event_callback):
        self.intercept_thread = KeyboardInterceptThread(key_event_callback)
        self.intercept_thread.start()
