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
import select
import struct

global tcount

tcount = 0

class Test:
	def __init__(self):
		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n\r\n"
		self.s = socket(AF_INET, SOCK_STREAM)
		self.cfg = conf.Config('etc/tempesta_fw.conf')
		self.cfg.add_option('cache', '0')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:80')

	def uri_len(self):
		global tcount

		self.res = False
		print("uri\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_uri_len', '3')
		self.cfg.add_end_of_section()
		self.vs_get = b"GET /index.html HTTP/1.0\r\nhost: loc\r\n\r\n"
		tfw.start_with_frang()
		self.s.connect(("127.0.0.1",8081))
		print("tfw start\n")
		try:
			self.s.send(self.vs_get)
			data = self.s.recv(1024)
			if len(data) == 0:
				self.res = True
				tcount += 1
		except OSError as e:
			print(e)
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()

	def request_rate(self):
		global tcount

		self.res = False
		print("req_rate\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('request_rate', '5')

		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.s.connect(("127.0.0.1",8081))


		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n" +\
b"Connection: Keep-Alive\r\n\r\n"
		try:
			for x in range(0, 15):
				self.s.sendall(self.vs_get)

		except OSError as e:
			self.res = True
			tcount += 1

		self.s.close()
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()

	def request_burst(self):
		global tcount

		self.res = False
		print("req_burst\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('request_burst', '1')

		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.s.connect(("127.0.0.1",8081))

		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n" +\
b"Connection: Keep-Alive\r\n\r\n"
		try:
			for x in range(0, 15):
				self.s.sendall(self.vs_get)

		except OSError as e:
			self.res = True
			tcount += 1

		self.s.close()
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()

	def conn_max(self):
		global tcount
		self.res = False
		print("conn_max\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('ip_block', 'on')
		self.cfg.add_option('concurrent_connections', '5')
		self.cfg.add_end_of_section()
		self.cfg.add_option('keepalive_timeout', '3')
		tfw.start_with_frang()
		print("tfw start\n")
		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n" +\
b"Connection: Keep-Alive\r\n\r\n"

		try:
			socks = []
			conncount = 0
			port = 8095
			for x in range(0,7):
				s = socket(AF_INET, SOCK_STREAM)
				s.settimeout(2)
				s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
				s.bind(('127.0.0.6', port))
				s.connect(("127.0.0.1", 8081))
				s.send(self.vs_get)
				socks.append(s)
				conncount += 1
				port += conncount
		except OSError as e:
			self.res = True
			tcount += 1

		for s in socks:
			s.shutdown(SHUT_RDWR)
			s.close()
			del s

		del socks
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()
		tfw.del_db()

	def conn_rate(self):
		global tcount
		self.res = False
		print("conn_rate\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('ip_block', 'on')
		self.cfg.add_option('connection_rate', '5')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n" +\
b"Connection: Keep-Alive\r\n\r\n"

		try:
			conncount = 0
			port = 8095
			for x in range(0,7):
				self.s = socket(AF_INET, SOCK_STREAM)
				self.s.settimeout(2)
				self.s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
				self.s.bind(('127.0.0.5', port))
				self.s.connect(("127.0.0.1", 8081))

				conncount += 1
				port += conncount

		except OSError as e:
			self.res = True
			tcount += 1

		print("res:", self.res)
		self.s.shutdown(SHUT_RDWR)
		self.s.close()
		time.sleep(5)
		tfw.stop()
		tfw.del_db()
	def ct_required(self):
		global tcount

		print("ct_required")
		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_required', 'true')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST / HTTP/1.0\r\nhost: loc\r\n" +\
b"Connection: Keep-alive\r\n\r\n"
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def conn_burst(self):
		global tcount

		self.res = False
		print("conn_burst\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('ip_block', 'on')
		self.cfg.add_option('connection_burst', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n" +\
b"Connection: Keep-Alive\r\n\r\n"

		try:
			conncount = 0
			port = 8095
			for x in range(0,7):
				self.s = socket(AF_INET, SOCK_STREAM)
				self.s.settimeout(2)
				self.s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
				self.s.bind(('127.0.0.7', port))
				self.s.connect(("127.0.0.1", 8081))

				conncount += 1
				port += conncount

		except OSError as e:
			self.res = True
			tcount += 1

		print("res:", self.res)
		self.s.shutdown(SHUT_RDWR)
		self.s.close()
		time.sleep(5)
		tfw.stop()
		tfw.del_db()

	def host_required(self):
		global tcount

		print("host_required")
		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_host_required', 'true')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST / HTTP/1.0\r\n" +\
b"Connection: Keep-alive\r\n\r\n"
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def body_len(self):
		global tcount

		print("body_len")
		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_vals', '[\"text/html\"]')
		self.cfg.add_option('http_body_len', '10')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST /a.html HTTP/1.0\r\nHost: loc\r\n" +\
b"Content-Type: text/html\r\n" +\
b"Content-Length: 20\r\n\r\n" +\
b"<html>content</html>\r\n\r\n"
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def field_len(self):
		global tcount

		print("field_len")
		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_vals', '[\"text/html\"]')
		self.cfg.add_option('http_field_len', '10')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST /a.html HTTP/1.0\r\nHost: loc\r\n" +\
b"Content-Type: application/xml\r\n" +\
b"Content-Length: 20\r\n\r\n" +\
b"<html>content</html>\r\n\r\n"
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()


	def ct_vals(self):
		global tcount

		print("ct_vals")
		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_vals', '[\"text/html\"]')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST / HTTP/1.0\r\nhost: loc\r\n" +\
b"Content-type: application/xml\r\n\r\n"
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def req_method(self):
		global tcount

		print("req_method")
		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_methods', 'get')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST / HTTP/1.0\r\nhost: loc\r\n" +\
b"Content-type: application/xml\r\n\r\n"
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()
	def header_chunks(self):
		global tcount

		print("header_chunks\n")

		part1 = b'GET / HTTP/1.0\r\n'
		part2 = b'host: loc\r\n'
		part3 = b'Connection: close\r\n\r\n'
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_header_chunk_cnt', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(part1)
		self.s.send(part2)
		self.s.send(part3)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1
		self.s.close()
		time.sleep(5)
		tfw.stop()
		print("res:", self.res)


	def header_timeout(self):
		global tcount
		part1 = b'GET / HTTP/1.0\r\n'
		part2 = b'host: loc\r\n\r\n'
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('client_header_timeout', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(part1)
		time.sleep(1)
		self.s.send(part2)
		data = self.s.recv(1024)
		if len(data) == 0:
			tcount += 1
			self.res = True
			print( "res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def body_timeout(self):
		global tcount
		print("body_timeout")
		part1 = b"POST /a.html HTTP/1.0\r\nHost: loc\r\n" +\
b"Content-Type: text/html\r\n" +\
b"Content-Length: 20\r\n\r\n" +\
b"<html>content" 
		part2 = b"</html>\r\n\r\n"

		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('client_body_timeout', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(part1)
		time.sleep(1)
		self.s.send(part2)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()

	def body_chunks(self):
		global tcount
		print("body_chunks")
		part1 = b"POST /a.html HTTP/1.0\r\nHost: loc\r\n" +\
b"Content-Type: text/html\r\n" +\
b"Content-Length: 30\r\n\r\n" +\
b"<html><body>content" 
		part2 = b"</body>"
		part3 = b"<html>\r\n\r\n"

		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_vals', '[\"text/html\"]')
		self.cfg.add_option('http_body_chunk_cnt', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.s = socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(part1)
		self.s.send(part2)
		self.s.send(part3)
		data = self.s.recv(1024)
		if len(data) == 0:
			self.res = True
			tcount += 1
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()



	def get_name(self):
		return 'test Frang'
	def run(self):
		tests = [self.body_chunks(), self.header_chunks(),\
 self.conn_burst(), self.request_burst(),\
 self.body_timeout(), self.field_len(), self.body_len(),\
 self.host_required(), self.ct_required(), self.req_method(),\
 self.ct_vals(), self.uri_len(), self.request_rate(), self.conn_rate(),\
 self.conn_max()]

		for f in tests:
			if hasattr(f, '__call__'):
				f()


		print("tests:{}/15".format(tcount))

