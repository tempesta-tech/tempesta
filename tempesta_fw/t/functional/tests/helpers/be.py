#!/usr/bin/env python
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

"""
A primitive back-end HTTP server implementation suitable for testing purposes.
"""
#import http.server 
import threading
import os
import sys
import signal
import SimpleHTTPServer
import BaseHTTPServer
from  SimpleHTTPServer import SimpleHTTPRequestHandler
import socket
import SocketServer

process_id = 0
server = None
def start(unlim):
	httpd = Server(('127.0.0.1', 8080), BackendHTTPRequestHandler)
	httpd.set_unlim(unlim)
	server = httpd
	server.socket.setblocking(0)
	pid = os.fork()
	if pid == 0:
		process_id = os.getpid()	
		print("fork - pid:{}".format(process_id))
		server.serve_forever()

def stop():
	if server != None:
		server.server_close()
		server.keep = False
	os.kill(process_id, signal.SIGTERM)
	sys.exit(0)

class Server(BaseHTTPServer.HTTPServer):
	def set_unlim(self,unlim):
		self.unlim = unlim

class BackendHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	
	def __init__(self, req, client_address, server):
		self. protocol_version = b'HTTP/1.0'
		SimpleHTTPRequestHandler.__init__(self, req, client_address,
						  server)
		print('be: handler_init:')

	


	def handle(self):
		if self.server.unlim == False: 
			self.close_connection = 0
		else:
			 self.close_connection = 1
		try:
			self.handle_one_request()
		except socket.error, e:
			if e[0] != errno.CONNRESET:
				raise

	def handle_one_request(self):
		print("me:handle_one:block")
		self.rfile._sock.setblocking(0)
		self.rfile._sock.settimeout(5)
		SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)

	def do_GET(self):
		resp = self.protocol_version + b' 200 - OK\r\n' +\
b'Date: Mon, 31 Oct 2016 06:41:19 GMT\r\n' +\
b'Server: python be\r\n'
		if self.server.unlim == False:
			resp += b'Content-Length: 0\r\n\r\n'
		else:
			resp += b'\r\n<html>content</html>\r\n\r\n'
		print("be:resp:{}".format(resp))
		self.wfile.write(resp)
		self.wfile.flush()
		if self.server.unlim:
			self.connection.close()

