#!/usr/bin/env python
__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'
import sys
from os.path import dirname, realpath, sep
import time
import types
sys.path.append(dirname(realpath(__file__))+ sep + sep + "helpers")

import conf
import tfw
from socket import *

# To check #490 duplicate headers issue we will need to set backend
# return duplicated headers in response. For Apache it would be
#mod_headers. If after two or more requests there aare responses - test pass.
class Test:
	def __init__(self):
		self.vs_get = b"GET http://localhost:80/ HTTP/1.1\r\n" + \
b"Host: localhost\r\n" + \
b"Connection: Keep-alive\r\n" + \
b"Set-Cookie: session=42\r\n\r\n"

		self.cfg = conf.Config("etc/tempesta_fw.conf")
		self.cfg.add_option('cache', '1')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:80')

	def get_name(self):
		return 'Test cache'

	def run(self):
		tfw.start()

		for x in range(0, 2):
			s = socket(AF_INET, SOCK_STREAM)
			s.connect(('127.0.0.1', 8081))
			s.sendall(self.vs_get)
			data = s.recv(1024)
		time.sleep(5)
		tfw.stop()

