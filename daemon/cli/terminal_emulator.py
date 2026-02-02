# Copyright 2026- by CHMOD 700 LLC. All rights reserved.
# This file is part of the SSHLog Software (SSHLog)
# Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3 (AGPLv3)

import sys
import tty
import termios
import threading
import select
import logging

logger = logging.getLogger('sshlog_client')

TERM_QUIT_KEY = b'\x11'  # CTRL+Q

class KeyboardInterceptThread(threading.Thread):

    def __init__(self, key_event_callback,
                 group=None, target=None, name=None, args=(), kwargs=None):
        super(KeyboardInterceptThread, self).__init__(group=group, target=target,
                                       name=name)
        self.key_event_callback = key_event_callback
        self._shutdown = False


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

            keypress, _, _ = select.select([fd], [], [], 0.25)
            if keypress:
                return sys.stdin.read(1048575)  # Big buffer to accommodate copy/paste
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, orig_fl)

        return None

    def shutdown(self):
        self._shutdown = True

    def run(self):

        #self.term_settings = termios.tcgetattr(sys.stdin)

        while not self._shutdown:
            keys = self.get_keys()
            if keys is None or len(keys) == 0:
                continue
            utf8_keys = keys.encode('utf-8')

            self.key_event_callback(utf8_keys)

            if utf8_keys == TERM_QUIT_KEY:
                break

        logger.debug("Exiting keyboard interrupt thread")
        #termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.term_settings)

class TerminalEmulator:
    def __init__(self, tty_id):
        self.tty_id = tty_id

    def update(self, bytes, num_bytes):

        sys.stdout.write(bytes)
        sys.stdout.flush()

    def shutdown(self):
        if self.intercept_thread is not None:
            self.intercept_thread.shutdown()

    def intercept_keyboard(self, key_event_callback):
        self.intercept_thread = KeyboardInterceptThread(key_event_callback)
        self.intercept_thread.start()
