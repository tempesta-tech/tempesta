#!/usr/bin/env python

# #490 Test of restoring of duplicate headers from cache.
# It tests fix of the #482 issue.
# The test adds two duplicate headers in the Apache config and sends 
# two requests then checks responses and the cache perf stat just for
# existence a cache event.

__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'
import sys
import time
import types

import conf
import teardown
import tfw
import tfwparser
from socket import *

class Test:
	def __init__(self):
		self.res = False
		self.vs_get = b"GET / HTTP/1.1\r\n"
		self.vs_get += b"Host: localhost\r\nConnection: Keep-alive\r\n"
		self.vs_get += "Cookie: session=42\r\n\r\n"
# 		A problem was with duplicate headers in a response.
#		So we add two geaders.
		self.apache_cfg = conf.ApacheConfig()
		self.apache_cfg.add_string('Header add Set-Cookie: \"s=42\"')
		self.apache_cfg.add_string('Header add Set-Cookie: \"s=42\"')
		self.cfg = conf.TFWConfig()
		self.cfg.add_option('cache', '2')
		self.cfg.add_option('cache_fulfill', '* *')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:80')


	def get_name(self):
		return 'Test cache'

	def run(self):
		func = tfw._stop_if_started()
		teardown.register(func)
		body_md5 = ""
		status = 0
		self.res = True
		parser = tfwparser.TFWParser()
		tfw.start()
		print('tfw started')

		for x in range(0, 2):
			s = socket(AF_INET, SOCK_STREAM)
			s.connect(('127.0.0.1', 8081))
			s.sendall(self.vs_get)
			data = s.recv(1024)
			if x == 0:
				body_md5 = parser.get_body_hash(data)
			else:
				if parser.get_body_hash(data) != body_md5:
					print("bodies not match")
					self.res = False
			status = parser.get_status(data)
			if status != 200:
				print("status:{}".format(status))
				self.res = False
			
			s.close()	
			
		stat = parser.check_cache_stat()
		if stat == 0:
			self.res = False
		print("perf stat:from cache:{}".format(stat))
		time.sleep(5)
		tfw.stop()
		self.apache_cfg.del_option('Header')
		print("Res:{}".format(self.res))
