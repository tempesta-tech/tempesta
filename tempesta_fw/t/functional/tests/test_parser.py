#!/usr/bin/env python
__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'
import sys

import conf
import tfw
import socket
class Test:
	def __init__(self):
		self.cfg = conf.Config('etc/tempesta_fw.conf')
		self.cfg.add_option('cache', '0')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:80')	
	def run(self):
		vs_get = b"POST /index.html HTTP/1.0\r\nHost: loc\r\n" +\
		b"Transfer-Encoding: chunked\r\nConnection: Keep-Alive" +\
		b"\r\n\r\n"+\
		b"16\r\n<html>content</html>\r\n\r\n0\r\n\r\n"

		tfw.start()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(("127.0.0.1",8081))
		s.sendall(vs_get)
		data = s.recv(1024)
		if len(data) > 0:
			print("res:{}".format(True))
		s.close()
		tfw.stop()

	def get_name(self):
		return 'test_chunked'	
