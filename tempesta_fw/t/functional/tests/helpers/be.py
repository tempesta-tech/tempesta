#!/usr/bin/env python
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'


"""
A primitive back-end HTTP server implementation suitable for testing purposes.
"""

import http.server
from threading import *

__author__ = 'NatSys Lab'
__copyright__ = 'Copyright (C) 2016 NatSys Lab. (info@natsys-lab.com).'
__license__ = 'GPL2'

def start(*args, **kwargs):
	"""A shortcut for BackendHTTPServer() constructor."""
	return BackendHTTPServer(*args, **kwargs)

def _dummy_callback(method, uri, headers, body):
	"""An example of a backend_callback passed to BackendHTTPServer()."""
	ret_code = 200
	ret_headers = { 'Content-Type': 'text/html; charset=utf-8' }
	ret_body = '<html><body>Hello from dummy back-end callback</body></html>'
	return (ret_code, ret_headers, ret_body)

class BackendHTTPServer(Thread):
	#Basically, this implementation does two things:
	# 1. It runs in a HTTP server in a separate thread.
	# 2. It handles all HTTP requests with a single backend_callback function
	# passed to the constructor.
	#
	# Also, right after initialization it blocks until a first TCP connection is.
	# accepted. That is done to wait until Tempesta FW is connected.
	# So you have to start Tempesta first, and only then spawn the HTTP server.
	def __init__(self, address, port=8080):
	# Initialize HTTP server, bind/listen/etc.
		super(BackendHTTPServer, self).__init__()
		self.httpd = http.server.HTTPServer((address, port), BackendHTTPRequestHandler)

	# Start a background thread that accept()s connections.
	# Synchronize with Tempesta FW.

	# Sleep until a first accepted connection (presumably from Tempesta FW).

	# FIXME: race conditions possible: after the connection is established,
	# the Tempesta FW must add the server to a load-balancing scheduler and
	#so on, so there is a time span, when the Tempesta is not yet ready to.
	# forward incoming requests to the connected back-end server. At this
	# point we just hope that this time span is negligible.
	# BTW, that may be fixed by exporting state of Temepsta FW via debugfs.
	# get_request() calls accept() that blocks until the first connection.
	# We just inject a synchronization with wait_for_tfw() there.
	def run(self):
		self.httpd.serve_forever()

	def stop(self):
		self.httpd.shutdown()
		self.httpd.socket.close()
		self.kill_received = True

class BackendHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):

	def __init__(self, req, client_address, server):
		super(BackendHTTPRequestHandler, self).__init__(req,
							client_address,	server)
	# A wrapper for BackendHTTPServer.backend_callback.
	# The class simply pushes HTTP requests to the callback, and then builds
	# responses from data returned by the callback.

	# That isdone for simplicity. It is easier to code a single callback function
	#than a whole handler class. We have to code one in every test, and we don't
	# need much power in tests code, so we prefer a function over a class.

	# Pass HTTP request to backend_callback, send a response containing data
	# returned by the callback.
	# Read body  and push it to the callback

	# The callback must return a tuple of exactly 3 elements:
	# (http_code, headers_dict, body_str)

	# Send response fields provided by the callback.

	# At this point Tempesta FW parser blocks HTTP/1.0 requests
protocol_version = 'HTTP/1.1'

	# Actual handler methods. We dispatch all them into our single function.
	def do_GET(self):
		self.wfile.write(b"Ok\n")
		self.wfile.flush()
		return

	def process_request(self, request, client_address):
		return

	# Add do_METHOD here if you need anything beyond GET and POST methods.
	# By default, the base class prints a message for every incoming request.
	# We don't want to see this flood in test results, so here is the stub.
	def log_message(self, format, *args):
		return
