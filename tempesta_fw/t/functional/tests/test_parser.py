#!/usr/bin/env python
__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'

import sys
from os.path import dirname, realpath, sep
print(dirname(realpath(__file__)))
sys.path.append((dirname(realpath(__file__)) + sep + "helpers"))

import socket
import tfw
import conf
import be


class Test:
	def __init__(self):
		self.cfg = conf.Config('etc/tempesta_fw.conf')
		self.cfg.add_option('cache', '0')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:8080')	
	def run(self):
		vs_get = b"GET / HTTP/1.0\r\nHost: loc\r\n" +\
		b"Connection: Keep-Alive\r\n\r\n"

		be.start(True)	
		tfw.start()
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(("127.0.0.1",8081))
		s.sendall(vs_get)
		data = s.recv(1024)
		s.close()
		tfw.stop()
		print('data:{}'.format(data))
		be.stop()

	def get_name(self):
		return 'test_unlimited'

t = Test()
t.run()	
