#!/usr/bin/env python
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

# A primitive back-end HTTP server implementation suitable for testing purposes.

import os
import sys
import signal
import SimpleHTTPServer
import BaseHTTPServer
from  SimpleHTTPServer import SimpleHTTPRequestHandler
import socket
import datetime
import time
import setproctitle

server = None

def handler(signum, frame):
	os.remove('be.pid')
	os._exit(0)

def start(unlim, resp):
	httpd = Server(('127.0.0.1', 8080), BackendHTTPRequestHandler)
	httpd.set_unlim(unlim)
	httpd.set_resp(resp)
	server = httpd
	server.socket.setblocking(0)
	pid = os.fork()
	if pid == 0:
		os.setsid()
		pid = os.fork()
		if pid == 0:
			setproctitle.setproctitle("tfwbackend")
			wd = os.open("be.pid", os.O_RDWR | os.O_CREAT)
			w = os.fdopen(wd, 'w')
			s_pid = str(os.getpid())
			w.write(s_pid)
			w.flush()
			w.close()
			signal.signal(signal.SIGUSR1, handler)
			server.serve_forever()
		else:
			os._exit(0)
# Wait while the child writes his pid. We can't wait it to the end (serve 
# forever). So let it is a fraction of a second. 
	time.sleep(0.2)
	rd = open("be.pid", 'a+')
	r_pid = rd.read()
	rd.close()
	return int(r_pid)	

def stop(pid):
	if server != None:
		server.server_close()
		server.shutdown()
		server.keep = False
	os.kill(pid, signal.SIGUSR1)

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
	def log_error(self, fmt, args):
# Supress a no essential timeout message.
		pass
	def handle(self):
		self.resp = self.server.resp
		if self.server.unlim == False: 
			self.close_connection = 0
		else:
			 self.close_connection = 1
		try:
			self.handle_one_request()
		except socket.error as e:
			if e[0] != errno.CONNRESET:
				raise

	def handle_one_request(self):
		self.rfile._sock.setblocking(0)
		self.rfile._sock.settimeout(0.2)
		SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)

	def do_GET(self):
		resp = self.server.resp

		self.wfile.write(resp)
		self.wfile.flush()
		if self.server.unlim:
			self.connection.close()

