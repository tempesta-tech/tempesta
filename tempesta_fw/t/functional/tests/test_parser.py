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
import tfwparser
import datetime
import os

class Test:
	def __init__(self):
		self.cfg = conf.Config('etc/tempesta_fw.conf')
		self.cfg.add_option('cache', '0')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:8080')
# Send request twice and check responses.
	def run_with_cache(self):
		self.cfg.del_option('cache')
		self.cfg.add_option('cache', '1')
		self.cfg.add_option('cache_fulfill', '* *')
		self.resp = b'HTTP/1.0' + b' 200 - OK\r\n'
		date = datetime.datetime.utcnow().strftime("%a, %d %b %Y" +\
							   " %H:%M:%S GMT")
		self.resp += b"Date: " + date + b"\r\n" 
		self.resp += b'\r\n<html>content</html>\r\n\r\n'
		self.run_test(2)
		 
# A response without the Content-Length header an without a body. 
# For now (11.11.2016) tempesta's return status - 404.
	def run_no_length_no_body(self):
		self.resp = b'HTTP/1.0' + b' 200 - OK\r\n'
		date = datetime.datetime.utcnow().strftime("%a, %d %b %Y" +\
							   " %H:%M:%S GMT")
		self.resp += b"Date: " + date + b"\r\n"
		self.resp += b"Server: be python\r\n\r\n"

		self.run_test(1)
# A response thithout the Content-Length header, but with a body.
	def run_no_length_body(self):
		self.resp = b'HTTP/1.0' + b' 200 - OK\r\n'
		date = datetime.datetime.utcnow().strftime("%a, %d %b %Y" +\
							   " %H:%M:%S GMT")
		self.resp += b"Date: " + date + b"\r\n" 
		self.resp += b'\r\n<html>content</html>\r\n\r\n'
		self.run_test(1)
	def run_test(self, num):

		vs_get = b"GET / HTTP/1.0\r\nHost: loc\r\n" +\
		b"Connection: Keep-Alive\r\n\r\n"
		pid =  be.start(True, self.resp)
		tfw.start()
		i = 0
		while i < num:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect(("127.0.0.1",8081))
			s.sendall(vs_get)
			data = s.recv(1024)
			s.close()
			i += 1
			if len(data) > 0:
				parser = tfwparser.TFWParser()
				parser.set_status(data)
				status = parser.get_status()
				print("status:{}".format(status))
			
		tfw.stop()	 
		be.stop(pid)

	def run(self):
		self.run_no_length_body()
		self.run_no_length_no_body()
		self.run_with_cache()

	def get_name(self):
		return 'test_unlimited'

t = Test()
t.run()	
