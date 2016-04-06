#!/usr/bin/env python3
__author__ = 'NatSys Lab'
__copyright__ = 'Copyright (C) 2016 NatSys Lab. (info@natsys-lab.com).'
__license__ = 'GPL2'
import sys
from os.path import dirname, realpath, sep
import time
#sys.path.append('./tests/helpers')
sys.path.append(dirname(realpath(__file__))+ sep + sep + "helpers")


import conf
import tfw
import socket
import select
import binascii
import struct


class Test:
	def __init__(self):
		self.vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n\r\n"
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		self.cfg = conf.Config('etc/tempesta_fw.conf')
		self.cfg.add_option('cache', '0')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:80')

	def set_uri(self):
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
			print("data:", data)
			print("uri ex\n")
#			raise socket.error(9, 'frang')
		except OSError as e:
			print("except:".format(e.errno))

		time.sleep(5)
		tfw.stop()

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
#			print("dt:", data)
		print( "time:", (time.clock() - startTime))
#			data = self.s.recv(5)
#			print("rec:", len(data))

	def conn_rate(self):
		print("conn_rate\n")
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('request_rate', '5')
		self.cfg.add_option('connection_rate', '5')
		self.cfg.add_option('connection_burst', '5')

		self.cfg.add_option('request_burst', '5')

		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		print("tfw start\n")
		try:
			for x in range(0,10):
				self.s = socket.socket(socket.AF_INET,								   socket.SOCK_STREAM)
				self.s.connect(("127.0.0.1", 8081))
				self.s.close()
				self.s.connect(('127.0.0.1', 8081))
				self.s.send(self.vs_get)
				data = self.s.recv(2048)
#			print(data)
		except OSError as e:
			print("conn except:{}\n".format(e.errno))

		self.s.close()
		time.sleep(5)
		tfw.stop()


	def get_name(self):
		return 'test Frang'
	def run(self):
		tests = [self.conn_rate(), self.set_request_rate(), \
			 self.set_uri()]
		for f in tests:
				f()


t = Test()
t.run()

