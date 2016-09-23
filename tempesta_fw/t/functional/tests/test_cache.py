#!/usr/bin/env python
__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'
import sys
import time
import types

import conf
import tfw
from socket import *

class Test:
	def __init__(self):
		self.res = False
		self.vs_get = b"GET http://localhost:80/ HTTP/1.1\r\n\
Host: localhost\r\nConnection: Keep-alive\r\nSet-Cookie: session=42\r\n\r\n"
# to reproduce the bug, a backend (apache) has to return in response double
# headers.
		self.apache_cfg = conf.Config('/etc/apache2/apache2.conf',
					      new=False)
		self.apache_cfg.add_string('Header add Set-Cookie: \"s=42\"')
		self.apache_cfg.add_string('Header add Set-Cookie: \"s=42\"')
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
			if len(data) > 0:
				self.res = True
				s.close()	
			else:
				self.res = False
				s.close()
		time.sleep(5)
		tfw.stop()
		print("Res:", self.res)
