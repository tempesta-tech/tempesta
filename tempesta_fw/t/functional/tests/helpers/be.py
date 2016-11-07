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
def start(unlim, resp):
	httpd = Server(('127.0.0.1', 8080), BackendHTTPRequestHandler)
	httpd.set_unlim(unlim)
	httpd.set_resp(resp)
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
	
	def set_resp(self, resp):
		self.resp = resp

class BackendHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	
	def __init__(self, req, client_address, server):
		self. protocol_version = b'HTTP/1.0'
		SimpleHTTPRequestHandler.__init__(self, req, client_address,
						  server)
#	def parse_request(self):
#		SimpleHTTPRequestHandler.parse_request(self)
	def log_error(self, fmt, args):
		pass
	def handle(self):
		self.resp = self.server.resp
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
		self.rfile._sock.setblocking(0)
		self.rfile._sock.settimeout(5)
		SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)

	def do_GET(self):
		resp = self.server.resp

		self.wfile.write(resp)
		self.wfile.flush()
		if self.server.unlim:
			self.connection.close()

