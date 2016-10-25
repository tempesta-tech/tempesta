#!/usr/bin/env python
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

"""
A primitive back-end HTTP server implementation suitable for testing purposes.
"""
import http.server 
import threading
import os
import sys
import signal

process_id = 0
server = None
def start():
	httpd = BackendHTTPServer(host='127.0.0.1', port=8080,
				  handler=BackendHTTPRequestHandler)
	server = httpd
	pid = os.fork()
	if pid > 0:
		process_id = os.getpid()
		print('is parent')
	else:
		process_id = os.getpid()	
		print("fork - pid:{}".format(process_id))
		server.run()

def stop():
	if server != None:
		server.server_close()
		server.keep = False
	os.kill(process_id, signal.SIGTERM)
	sys.exit(0)
	
class BackendHTTPServer(http.server.HTTPServer):
# A simple backend http server.	
	def __init__(self, host, port, handler):
	# Initialize HTTP server, bind/listen/etc.
		self.keep = True
		super(BackendHTTPServer, self).__init__((host, port), handler)

	def run(self):
		self.close_connection = 0
		while self.keep:
			self.handle_request()
			

	def stop(self):
		self.keep = False
		self.shutdown()
		self.httpd.socket.close()
		self.kill_received = True
		
#	def handle_request(self):
#		print("be:", "handle")
#		super()

class BackendHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

	def __init__(self, req, client_address, server):
		print('be: handler_init:', self.raw_requestline)
		super(BackendHTTPRequestHandler, self).__init__(req,
							client_address,	server)

	protocol_version = 'HTTP/1.0'

	def do_GET(self):
		print("be:", "do_GET")
		self.wfile.write(b"Ok\n")
		self.wfile.flush()
		return super()

