#!/usr/bin/env python

# #629 A set of tests for responses without the "Content-Length:" header.
# In this set we using be.py as backend server to full control of the responses.# We set a response for the backend, send a request to the Tempesta,
# get a ressponse from the Tempesta and check it.
# For a test with cache we also check the cache perf stat.

__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'

import sys

import socket
import tfw
import conf
import be
import tfwparser
import datetime
import os
import requests

class Test:
	def __init__(self):
		self.res = ""
		self.cfg = conf.TFWConfig()
		self.cfg.add_option('cache', '0')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:' +
				    str(conf.get_beport()))
# 	Send request twice and check responses.
	def run_with_cache(self):
		self.res = "cache - two queries and compare bodies:\n"
		self.cfg.del_option('cache')
		self.cfg.add_option('cache', '1')
		self.cfg.add_option('cache_fulfill', '* *')

		self.run_test(2)
		parser = tfwparser.TFWParser()
		 
		 
# 	A response without the Content-Length header and without a body.
#	It checks state of the #629 issue.
	def run_no_length_no_body(self):
		self.res = "no Content-Length header and no body:\n"


		self.run_test(1)
# A test without the Content-Length header, but with a body in a response.     
	def run_no_length_body(self):
		self.res = "no Content-Length header, but is body:\n"
		
		self.run_test(1)
	def run_test(self, num):

		vs_get = b"GET / HTTP/1.1\nHost: loc\n" +\
		b"Connection: Keep-Alive\r\n\r\n"
		parser = tfwparser.TFWParser()
		body_hash = parser.get_body_hash(self.resp)
		
		tfw.start()
		i = 0
		while i < num:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			data = ""
			s.connect(("127.0.0.1",8081))
			s.settimeout(1)
			try:
				s.sendall(vs_get)
				data = s.recv(1024)
			except socket.error as e:
				self.res = "exception:{}".format(e)
				print("exception:{}".format(e))

			s.close()
			i += 1
			if len(data) > 0:
				parser = tfwparser.TFWParser()
				if len(parser.get_body(data)) == 0:
					self.res += 'no body\n'
				else:
					b_hash = parser.get_body_hash(data)
					if b_hash != body_hash:
						self.res += "bodies "
						self.res += "not equals\n"
					else:
						self.res += "bodies equals\n"
				status = parser.get_status(data)
				self.res += "status:{}\n".format(status)
		if num > 1:
			cache_stat = parser.check_cache_stat()
			self.res +="perf stat: from cache="
			self.res += str(cache_stat) + '\n'
		tfw.stop()	 
		
		print(self.res)

	def run(self):
		self.resp = b'HTTP/1.1' + b' 200 - OK\n'
		date = datetime.datetime.utcnow().strftime("%a, %d %b %Y" +\
							   " %H:%M:%S GMT")
		self.resp += b"Date: " + date + b"\r\n"
		self.resp += b"Server: be python\r\n" 
		self.resp += b'\r\n<html><body>content</body></html>\r\n\r\n'
		be_pid =  be.start(True, self.resp)
		self.run_no_length_body()
		self.run_no_length_no_body()
		self.run_with_cache()
		be.stop(be_pid) 

	def get_name(self):
		return 'test_unlimited'

