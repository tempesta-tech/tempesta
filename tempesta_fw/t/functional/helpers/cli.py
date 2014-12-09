"""
HTTP client emulator.

These tests are built around a network of three participants: client, server and
a running Tempesta FW instance. This module is responsible for the client part.
It allows to connect to the Tempesta and send some data to it in various ways.   
"""

from socket import *

__author__ = 'NatSys Lab'
__copyright__ = 'Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).'
__license__ = 'GPL2'

def send_raw_fragments(str_list, port=80, timeout_sec=5):
    s = create_connection(('127.0.0.1', port), timeout_sec)
    for frag in str_list:
        buf = bytes(frag, 'UTF-8')
        s.sendall(buf)
    s.close()
