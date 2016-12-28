"""
Implementation of a "teardown" routine which is executed after every test.

A problem: Python interpreter doesn't exit until all threads are exited.
That means that when a test finishes, it hangs if there are backend threads
running in background. So these threads should be terminated somehow.
We don't want to write some boilerplate code at the end of each test,
so here we have code that does it automatically.
"""

import os
import sys
from threading import *

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2014-2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

_main_thread = current_thread()
_teardown_hooks = []
_stderr_write_event = Event()

def register(hook_fn, *args, **kwargs):
    """
    Register a hook which is executed when the main thread terminates.
    
    The atexit.register() doesn't work because we terminate all threads
    asynchronously via os._exit(). So this function is a drop-in replacement
    that works in our case.
    """
    entry = (hook_fn, args, kwargs)
    _teardown_hooks.append(entry)

def _call_hooks_when_main_exits():
    """
    Wait until the main thread exits, and then terminate all remaining threads
    by sending them a signal. Also execute all register()'ed hooks.
    """
    _main_thread.join()
    for hook_fn, args, kwargs in _teardown_hooks:
        hook_fn(*args, **kwargs)
    os._exit(-1 if _stderr_write_event.is_set() else 0)

# Start another thread to catch a moment when the main thread exits.
# It turns out there is no cleaner solution because the Thread class doesn't
# provide any way to add exit hooks.
Thread(target=_call_hooks_when_main_exits).start()

# Unfortunately, we can't obtain an exit code of a Thread after it exits.
# So we detect errors by the fact of writing to the stderr stream.
# We wrap sys.stderr and set the error flag if someone writes a message there.
class StdstreamWrapper():
    def __init__(self, stream):
        self.stream = stream
    
    def write(self, data):
        _stderr_write_event.set()
        self.stream.write(data)

sys.stderr = StdstreamWrapper(sys.stderr)
