#!/usr/bin/env python

# #375 Test of the Frang classifier.

# The test consists of a number of tests for different limits of the Frang.
# Each test sets a frang limit to the Tempesta configuration, starts 
# the Tempesta with the Frang, then tries a set of requests or a request which
# exceeds
# the limit and detect blocking of the requests or closing of a client 
# connection.
# The tests catch an exceptions, but not handle them to enable to run other
# tests.
__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016-2017 Tempesta Technologies.'
__license__ = 'GPL2'
import sys
from os.path import dirname, realpath, sep
import time
import types

import conf
import tfw
from socket import *
import select
import struct
import socket
import tfwparser
global tcount

tcount = 0

class Test:

	def __init__(self):
		self.vs_get = b"GET / HTTP/1.1\r\nhost: loc\r\n\r\n"
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.cfg = conf.TFWConfig()
		self.parser = tfwparser.TFWParser()
		self.cfg.add_option('cache', '0')
		self.cfg.add_option('listen', '8081')
		self.cfg.add_option('server', '127.0.0.1:80')

	def uri_len(self):
		"""
		The function checks the uri lengh frang limit, so we send 
		a request that
		contains the uri with length greater than limit was set. 
		If frang blocks	request, the Tempesta  returns no data and
		the Frang writes a warning to the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_uri_len', '3')
		self.cfg.add_end_of_section()
		self.vs_get = b"GET /index.html HTTP/1.1\r\nhost: loc\r\n\r\n"
		tfw.start_with_frang()
		self.s.connect(("127.0.0.1",8081))
		try:
			self.s.send(self.vs_get)
			data = self.s.recv(1024)
		except OSError as e:
			pass
		if self.parser.check_log("URI length exceeded"):
			self.res = True
			tcount += 1
		print("uri len:res:{}".format(self.res))
		time.sleep(5)
		tfw.stop()

	def request_rate(self):
		"""
		The function checks requests per second frang limit. We send a number
		of requests from a connection. 
		After a moment when amount of requests became greater
		than set limit,the frang starts bloocking new requests
		and client connection is closed,the Frang writes a warning to
		the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('request_rate', '2')

		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		self.s.connect(("127.0.0.1",8081))

		self.vs_get = b"GET / HTTP/1.1\r\nhost: loc\r\n"
		self.vs_get += b"Connection: Keep-Alive\r\n\r\n"
		try:
			for x in range(0, 5):
				self.s.sendall(self.vs_get)
				data = self.s.recv(1024)

		except socket.error as e:
			pass	
		if self.parser.check_log("request rate exceeded"):
			self.res = True
			tcount += 1 
		self.s.close()
		print("request rate:res:{}".format(self.res))
		time.sleep(5)
		tfw.stop()

	def request_burst(self):
		"""
		The function checks the number of requests per fraction of a
		second frang limit. We send a number of requests. When amoun
		of requests became greater them limit that was set, the frang
		blocks new requests and	the Tempesta closes a clientconnection.
		The Frang writes a warning in the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('request_burst', '1')

		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		self.s.connect(("127.0.0.1",8081))

		self.vs_get = b"GET / HTTP/1.1\r\nhost: loc\r\n"
		self.vs_get += b"Connection: Keep-Alive\r\n\r\n"
		try:
			for x in range(0, 15):
				self.s.sendall(self.vs_get)
				data = self.s.recv(1024)

		except socket.error as e:
			pass
		if self.parser.check_log("requests burst exceeded"):
			self.res = True
			tcount += 1
		self.s.close()
		print("requests burst:res:{}".format(self.res))
		time.sleep(5)
		tfw.stop()

	def conn_max(self):
		"""
		The function checks the concurrent connections per client frang
		limit. We connecting to the Tempesta from one address, but from
		different ports. After a momet when amount of oconnections
		becames greater than limit, the Tempesta seases to accept new
		connections  and the Frang writes a warning to a log.
		"""
		global tcount
		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('ip_block', 'off')
		self.cfg.add_option('concurrent_connections', '5')
		self.cfg.add_end_of_section()
		self.cfg.add_option('keepalive_timeout', '3')
		tfw.start_with_frang()
		self.vs_get = b"GET / HTTP/1.1\r\nhost: loc\r\n"
		self.vs_get += b"Connection: Keep-Alive\r\n\r\n"

		try:
			socks = []
			for x in range(0,7):
				s = socket.socket(AF_INET, SOCK_STREAM)
				s.settimeout(2)
				s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
				s.connect(("127.0.0.1", 8081))
				s.send(self.vs_get)
				data = s.recv(1024)
				socks.append(s)
		except socket.error as e:
			pass	
		for s in socks:
			s.shutdown(SHUT_RDWR)
			s.close()
			del s

		del socks
		if self.parser.check_log("connections max num. exceeded"):
			self.res = True
			tcount += 1
		print("conn max:res:{}".format(self.res))
		time.sleep(20)
		tfw.stop()

	def conn_rate(self):
		"""
		The function  checks the connections from a client per second
		frang limit.We connecting to the Tempesta from different ports
		and one address.
		When number of connections exceeds limit the frang will block
		new connections and write a warning to the log.
		"""
		global tcount
		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('ip_block', 'off')
		self.cfg.add_option('connection_rate', '5')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		self.vs_get = b"GET / HTTP/1.1\r\nhost: loc\r\n"
		self.vs_get += b"Connection: Keep-Alive\r\n\r\n"

		socks = []
		try:
			for x in range(0,7):
				s = socket.socket(AF_INET, SOCK_STREAM)
				s.settimeout(2)
				s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
				s.connect(("127.0.0.1", 8081))
				socks.append(s)

		except socket.error as e:
			pass
		if self.parser.check_log("new connections rate exceeded"):
			self.res = True
			tcount += 1

		print("conn rate:res:{}".format(self.res))
		for s in socks:
			s.shutdown(SHUT_RDWR)
			s.close()
			del s
		del socks
		time.sleep(20)
		tfw.stop()

	def ct_required(self):
		"""
		The function checks the presence of the "Content-Type"
		header frang limit. We set the ct_required frang limit and
		send a request without the header "Content-Type" and expect the
		frang blocks request, writes a warning to the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_required', 'true')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST / HTTP/1.1\r\nhost: loc\r\n"
		self.vs_get += b"Connection: Keep-alive\r\n\r\n"
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if self.parser.check_log("Content-Type header field"):
			self.res = True
			tcount += 1

		print("ct required:res:{}".format(self.res))
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def conn_burst(self):
		"""
		The function checks the connections per a fraction of a second
		frang limit. We make a number of connections from different
		ports of one address. When amount of connections reaches the
		limit, the Frang writes a warning at the log.
		""" 
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('ip_block', 'off')
		self.cfg.add_option('connection_burst', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		self.vs_get = b"GET / HTTP/1.1\r\nhost: loc\r\n"
		self.vs_get += b"Connection: Keep-Alive\r\n\r\n"

		try:
			socks = []
			conncount = 0
			for x in range(0,7):
				s = socket.socket(AF_INET, SOCK_STREAM)
				s.settimeout(2)
				s.connect(("127.0.0.1", 8081))
				socks.append(s)

		except socket.error as e:
			pass
		if self.parser.check_log("new connections burst exceeded"):
			self.res = True
			tcount += 1 
		for s in socks:
			s.close()
			del s
		print("conn burst:res:{}".format(self.res))

		time.sleep(5)
		tfw.stop()

	def host_required(self):
		"""
#		The function checks the presence of the "Host" header frang limit.
#		We set the limit and send a requests without "Host" header. 
#		So the frang blockthe request and the Frang writes a warning at
		the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_host_required', 'true')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST / HTTP/1.1\r\n"
		self.vs_get += b"Connection: Keep-alive\r\n\r\n"
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if self.parser.check_log("Host header field"):
			self.res = True
			tcount += 1

		print("host required:res:{}".format(self.res))
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def body_len(self):
		"""
		The function checks the length of request`s body frang limit. 
		We set the limit and send a request with a body greater than
		the limit. So the frang blocks the request and writes
		a warning at the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_vals', '[\"text/html\"]')
		self.cfg.add_option('http_body_len', '10')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST /a.html HTTP/1.1\r\nHost: loc\r\n"
		self.vs_get += b"Content-Type: text/html\r\n"
		self.vs_get += b"Content-Length: 20\r\n\r\n"
		self.vs_get += b"<html>content</html>\r\n\r\n"
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if self.parser.check_log("body length exceeded"):
			self.res = True
			tcount += 1

		print("body len:res:{}".format(self.res))
		self.s.close()
		time.sleep(5)
		tfw.stop()
 
	def field_len(self):
		"""
		The function checks the header field length frang limit. We set
		the limit and send a request with a header greater than limit.
		The frang blocks the request and the Frang writes a warning at
		the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_field_len', '10')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST /a.html HTTP/1.1\r\nHost: loc\r\n"
		self.vs_get += b"Content-Type: application/xml\r\n"
		self.vs_get += b"Content-Length: 20\r\n\r\n"
		self.vs_get += b"<html>content</html>\r\n\r\n"
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if self.parser.check_log("field length exceeded"):
			self.res = True
			tcount += 1

		print("field len:res:{}".format(self.res))
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def ct_vals(self):
		"""
		The function checks the permitted values of the "Content-Type"
		header frang limit. We add a set of the "Content-Type"
		permitted values to the frang section. 	And then send a request
		with a "Content-Type" header value witch is not present in the
		added set. The frang blocks the request and the Frang
		writes a warning at the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_vals', '[\"text/html\"]')
		self.cfg.add_end_of_section()
		self.vs_get = b"POST / HTTP/1.1\r\nhost: loc\r\n"
		self.vs_get += b"Content-type: application/xml\r\n\r\n"
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if self.parser.check_log("restricted Content-Type"):
			self.res = True
			tcount += 1

		print("ct vals:res:{}".format(self.res))
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def req_method(self):
		"""
		The function checks the permitted request methods frang limit.
		We add a set of request method to the frang limits and send
		a request with arequest method
		witch is not present in the set. So the frang have to block
		the request and to write a warning to the log.
		"""
		global tcount

		self.res = False
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_methods', 'get')
		self.cfg.add_end_of_section()
		self.vs_get =  b"POST / HTTP/1.1\r\nhost: loc\r\n"
		self.vs_get += b"Content-type: application/xml\r\n\r\n"
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(self.vs_get)
		data = self.s.recv(1024)
		if self.parser.check_log("restricted HTTP method"):
			self.res = True
			tcount += 1

		print("request method:res:{}".format(self.res))
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def header_chunks(self):
		"""
		The function checks the amount of a header chunks frang limit.
		We set the limit and divide request`s headers into parts and
		send parts separate. So the frang blocks the request and writes
		a warning at the log.
		"""
		global tcount
		part1 = b'GET / HTTP/1.1\r\n'
		part2 = b'host: loc\r\n'
		part3 = b'Connection: close\r\n\r\n'
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_header_chunk_cnt', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.setsockopt(socket.IPPROTO_TCP, TCP_NODELAY, 1)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(part1)
		self.s.send(part2)
		self.s.send(part3)
		data = self.s.recv(1024)
		if self.parser.check_log("header chunk count exceeded"):
			self.res = True
			tcount += 1
		self.s.close()
		time.sleep(5)
		tfw.stop()
		print("header chunks:res:{}".format(self.res))

	def header_timeout(self):
		"""
		The function checks the timeout between a request header chunks
		frang limit.
		We set the limit, then send a request header divided into parts
		with a pause between the parts. The frang blocks the request
		and writes a warning at the log.
		"""
		global tcount
		part1 = b'GET / HTTP/1.1\r\n'
		part2 = b'host: loc\r\n\r\n'
		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('client_header_timeout', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.setsockopt(socket.IPPROTO_TCP, TCP_NODELAY, 1)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(part1)
		time.sleep(1)
		self.s.send(part2)
		data = self.s.recv(1024)
		if len(data) == 0:
			tcount += 1
			self.res = True

			print( "header timeout:res:{}".format(self.res))
		self.s.close()
		time.sleep(5)
		tfw.stop()

	def body_timeout(self):
		"""
		The function checks the timeout between body chunks frang
		limit. We set the limit and divide our request into parts
		that a body is divided.
	Then send the parts with a pause. The frang has to bock the request 
	and writes a warning at the log.
		"""
		global tcount
		self.res = False
		part1 = b"POST /a.html HTTP/1.1\r\nHost: loc\r\n"
		part1 += b"Content-Type: text/html\r\nContent-Length: 20"
		part1 += b"\r\n\r\n<html>content"
		part2 = b"</html>\r\n\r\n"

		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_vals', '[\"text/html\"]')
		self.cfg.add_option('client_body_timeout', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.setsockopt(socket.IPPROTO_TCP, TCP_NODELAY, 1)
		self.s.connect(('127.0.0.1', 8081))
		self.s.send(part1)
		time.sleep(2)
		self.s.send(part2)
		data = self.s.recv(1024)
		if self.parser.check_log("body timeout exceed"):
			tcount += 1
			self.res = True
			
		print("body timeout:res:{}".format(self.res))
		self.s.close()
		time.sleep(5)
		tfw.stop()
 
	def body_chunks(self):
		"""
		The function checks the amount of a body chunks frang limit.
		We set the limit. Then divide our request into parts that
		the body of the request was divided too And send the parts with
		a pause. The frang has to block the request. and to write
		a warnining at the log.
		"""
		global tcount
		self.res = False
		part1 = b"POST /a.html HTTP/1.1\r\nHost: loc\r\n\
Content-Type: text/html\r\nContent-Length: 30\r\n\r\n<html><body>content"
		part2 = b"</body>"
		part3 = b"<html>\r\n\r\n"

		self.__init__()
		self.cfg.add_section('frang_limits')
		self.cfg.add_option('http_ct_vals', '[\"text/html\"]')
		self.cfg.add_option('http_body_chunk_cnt', '1')
		self.cfg.add_end_of_section()
		tfw.start_with_frang()
		self.s = socket.socket(AF_INET, SOCK_STREAM)
		self.s.setsockopt(socket.IPPROTO_TCP, TCP_NODELAY, 1)
		self.s.connect(('127.0.0.1', 8081))
		try:
			self.s.send(part1)
			self.s.send(part2)
			self.s.send(part3)
			data = self.s.recv(1024)
		except socket.error as e:
			pass
		
		if self.parser.check_log("body chunk count exceed"):
			self.res = True
			tcount += 1

		print("body chunks:res:{}".format(self.res))
		time.sleep(5)
		tfw.stop()

	def get_name(self):
		return 'test Frang'

	def run(self):
		global tcount
		conf.set_msg_cost()
		tests = [self.request_burst(), self.body_chunks(),
			 self.header_chunks(), self.body_timeout(),
			 self.uri_len(), self.field_len(), self.body_len(),
			 self.host_required(), self.ct_required(), 
			 self.ct_vals(), self.conn_rate(), self.req_method(),
			 self.request_rate(), self.conn_max(), self.conn_rate()] 
		for f in tests:
			if hasattr(f, '__call__'):
				f()

		print("tests:{}/15".format(tcount))

