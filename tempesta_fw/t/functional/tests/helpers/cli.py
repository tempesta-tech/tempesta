__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2014-2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

"""
HTTP client emulator.

These tests are built around a network of three participants: client, server and
a running Tempesta FW instance. This module is responsible for the client part.
It allows to connect to the Tempesta and send some data to it in various ways.   
"""

from socket import *
from contextlib import contextmanager



@contextmanager
def connect_to_tfw(port=80, timeout_sec=5):
    socket = create_connection(('127.0.0.1', port), timeout_sec)
    yield socket
    socket.close()
