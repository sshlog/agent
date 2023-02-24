# -*- coding: utf-8 -*-

# pidlockfile/pidlockfile.py

# PID lock file implementation for use with
# ‘python-daemon’, an implementation of PEP 3143.
#
# Copyright © 2018 Alexei Igonine <aigonine@gmail.com>
#
# This is free software: you may copy, modify, and/or distribute this work
# under the terms of the Apache License, version 2.0 as published by the
# Apache Software Foundation.
# No warranty expressed or implied. See the file ‘LICENSE.ASF-2’ for details.

from __future__ import (absolute_import, unicode_literals)

import os
import time
import fcntl
import errno

class LockTimeout(Exception):
    """Raised when lock creation fails within a user-defined period of time."""
    def __init__(self, path):
        msg = "Timeout waiting to acquire lock for {0}".format(path)
        super(LockTimeout, self).__init__(msg)

class AlreadyLocked(Exception):
    """Some other process is locking the file."""
    def __init__(self, path):
        msg = "{0} is already loocked ".format(path)
        super(AlreadyLocked, self).__init__(msg)

class PIDLockFile(object):
    """ Lockfile with acquire timeout, implemented as a Unix PID file

        The class implements context manager interface.Lock is managed
        by using fcntl calls. That allows automatic lock release in case
        of unexpected termination of daemon process.

        """

    def __init__(self, path, timeout=None):
        """ Set up the parameters of a PIDLockFile instance.
        Args:
            path: Filesystem path to the PID file.
            timeout: Value in seconds used as a lock acquire timeout.
                If not specified, the process will be waiting for lock
                acquisition indefinitely.
        """

        self.timeout = timeout
        self.path = path
        self.pidfile = None

    def __enter__(self):
        """Context manager interface support"""
        self._acquire()

    def __exit__(self, *_exc):
        """Context manager interface support"""
        self._release()

    def _acquire(self):
        """ Acquire the lock.

        * Creates PID file if it does not exist
        * Locks the file. Depending on timeout parameter
          either waits for the lock to be acquired or
          raises an exception:
          * If timeout is not specified (the default) - waits
            indefinitely for the lock to be acquired
          * If timeout is 0 and lock can't be acquired immediately
            raises AlreadyLocked exception
          * If timeout is > 0, tries to acquire lock for timeout seconds
            and if not successful, raises LockTimeout exeption
        * Writes process PID into the lock file
        """
        timeout = self.timeout
        end_time = None
        lock_mode = fcntl.LOCK_EX
        if timeout is not None:
            lock_mode |= fcntl.LOCK_NB
            if timeout > 0:
                end_time = time.time() + timeout
        while True:
            pf = None
            try:
                pf = open(self.path, "r+")
                while True:
                    try:
                        fcntl.flock(pf, lock_mode)
                        break
                    except IOError as e:
                        if e.errno in (errno.EACCES, errno.EAGAIN):
                            if end_time is None:
                                raise AlreadyLocked(self.path)
                            else:
                                if time.time() > end_time:
                                    raise LockTimeout(self.path)
                                time.sleep(float(timeout) / 10)
                pf.truncate()
                pf.write("{0}\n".format(os.getpid()))
                pf.flush()
                self.pidfile = pf
                break
            except IOError as e:
                if e.errno == errno.ENOENT:
                    open_flags = (os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    open_mode = 0o644
                    try:
                        os.close(os.open(self.path, open_flags, open_mode))
                    except IOError as ee:
                        if ee.errno == errno.EEXIST:
                            pass
            except:
                if pf is not None:
                    pf.close()
                raise

    def _release(self):
        """ Release the lock.
        """
        if self.pidfile is not None:
            self.pidfile.close()

    def is_locked(self):
        """ Check if the PID file is locked by some other process

            If file is not locked returns None.
            If file is locked, returns PID of the locking process
        """
        try:
            with open(self.path, "r") as pf:
                try:
                    fcntl.flock(pf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return None
                except IOError as e:
                    if e.errno in (errno.EACCES, errno.EAGAIN):
                        return int(pf.readline().strip())
                    else:
                        raise
        except IOError as e:
            if e.errno == errno.ENOENT:
                return None
            else:
                raise
