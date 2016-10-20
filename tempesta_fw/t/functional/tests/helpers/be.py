#!/usr/bin/env python
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

"""
A primitive back-end HTTP server implementation suitable for testing purposes.
"""
import http.server 
import threading

class BackendHTTPServer(http.server.HTTPServer):
# A simple backend http server.	
	def __init__(self, address, port=8080):
	# Initialize HTTP server, bind/listen/etc.
		self.keep = True
		super(BackendHTTPServer, self).__init__((address, port), BackendHTTPRequestHandler)

	def run(self):
		thread = threading.Thread(target=self.handle_request())
		thread.start()

	def stop(self):
		self.keep = False
		self.shutdown()
		self.httpd.socket.close()
		self.kill_received = True
		
#	def handle_one_request():
#		print("be:", "handle_one_request") 

class BackendHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

	def __init__(self, req, client_address, server):
		super(BackendHTTPRequestHandler, self).__init__(req,
							client_address,	server)

	protocol_version = 'HTTP/1.1'

	def do_GET(self):
		print("be:", "do_GET")
		self.wfile.write(b"Ok\n")
		self.wfile.flush()
		return super()

