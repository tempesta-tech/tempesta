#!/usr/bin/env python
__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'
import sys
from os.path import dirname, realpath, sep
import time
import types
#sys.path.append('./tests/helpers')
sys.path.append(dirname(realpath(__file__))+ sep + sep + "helpers")


import conf
import tfw
from socket import *
import select
import binascii
import struct


class Test:
	def __init__(self):
		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n"
		self.s = socket(AF_INET, SOCK_STREAM)

		self.cfg = conf.Config('etc/tempesta_fw.conf')
		self.cfg.add_option('cache', '0')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:80')

	def uri_len(self):
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
		except OSError as e:
			print(e)
		time.sleep(5)
		tfw.stop()
		print("res:", self.res)

	def request_rate(self):
		self.res = False
		print("req_rate\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
#		self.cfg.add_option('request_rate', '5')
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
#				data = self.s.recv(1024)

		except OSError as e:
			self.res = True

		self.s.close()
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()

	def request_burst(self):
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
#				data = self.s.recv(1024)

		except OSError as e:
			self.res = True

		self.s.close()
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()

	def conn_max(self):
		self.res = False
		print("conn_max\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('ip_block', 'on')
		self.cfg.add_option('concurrent_connections', '5')


		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n" +\
b"Connection: Keep-Alive\r\n\r\n"

		try:
			socks = []
			conncount = 0
			port = 8095
			for x in range(0,3):
				s = socket(AF_INET, SOCK_STREAM)
				s.settimeout(2)
				s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
				s.bind(('127.0.0.6', port))
				s.connect(("127.0.0.1", 8081))
				socks.append(s)
				print(len(socks)) 
				conncount += 1
				port += conncount
#				time.sleep(0.55555)
		except OSError as e:
			print("max except:", e)
			self.res = True

		print("res:", self.res)
#		self.s.shutdown(SHUT_RDWR)
#		self.s.close()
		for s in socks:
			s.shutdown(SHUT_RDWR)
			s.close()
#			socks.remove(s)
			del s
#			time.sleep(0.2)

		del socks
		print("sks:", "after del")

#		time.sleep(5)
#		tfw.stop()
#		tfw.del_db()

	def conn_rate(self):
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

		print("res:", self.res)
		self.s.shutdown(SHUT_RDWR)
		self.s.close()
		time.sleep(5)
		tfw.stop()
		tfw.del_db()
	def ct_required(self):
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

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def host_required(self):
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

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def body_len(self):
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

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def field_len(self):
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

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()


	def ct_vals(self):
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

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def req_method(self):
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

		print("res:", self.res)
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def header_timeout(self):
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
		print(data)

	def body_timeout(self):
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
		print("res:", self.res)
		time.sleep(5)
		tfw.stop()


	def get_name(self):
		return 'test Frang'
	def run(self):
#		tests = [self.conn_rate()]
		tests = [self.request_burst(), self.body_timeout(),\
 self.field_len(),\
 self.body_len(),\
 self.host_required(), \
 self.ct_required(), self.req_method(), self.ct_vals(), self.uri_len(),\
 self.request_rate(),\
 self.conn_rate()]

		tcount = 0
		for f in tests:
			tcount += 1
			if hasattr(f, '__call__'):
				f()

		print("tests:{}".format(tcount))

t = Test()
t.run()

