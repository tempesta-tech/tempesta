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
		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n\r\n"
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
			print("data:", len(data))
			if len(data) == 0:
				self.res = True
		except OSError as e:
			print("except:".format(e.errno))

		time.sleep(5)
		tfw.stop()
		print("res:", self.res)

	def set_request_rate(self):
		print("req_rate\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('request_rate', '5')
		self.cfg.add_option('connection_rate', '5')
		self.cfg.add_option('request_burst', '5')

		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		self.s.connect(("127.0.0.1",8081))


		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n" +\
b"Connection: Keep-Alive\r\n\r\n"
		startTime = time.clock()
		try:
			for x in range(0, 9):
				self.s.sendall(self.vs_get)
				data = self.s.recv(1024)

		except OSError as e:
			print("req except:{}\n".format(e.errno))

		self.s.close()
		time.sleep(5)
		tfw.stop()
		print( "time:", (time.clock() - startTime))

	def conn_rate(self):
		self.res = False
		print("conn_rate\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('ip_block', 'on')
		self.cfg.add_option('concurrent_connections', '5')
		self.cfg.add_option('connection_rate', '5')
		self.cfg.add_option('connection_burst', '5')

		self.cfg.add_option('request_burst', '5')

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
				print(conncount)
		except OSError as e:
			self.res = True
		else:
			self.res = False
		finally:
			pass
		print("res:", self.res)
		self.s.shutdown(SHUT_RDWR)
		self.s.close()
		time.sleep(5)
		tfw.stop()
		tfw.del_db()

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

	def get_name(self):
		return 'test Frang'
	def run(self):
		tests = [self.conn_rate(), self.uri_len()]
		for f in tests:
			if hasattr(f, '__call__'):
				f()
				print("res:\n", self.res)


t = Test()
t.run()

