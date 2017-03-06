from __future__ import print_function
import abc
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from . import framework


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Request(BaseHTTPRequestHandler):
    """HTTP request representation."""

    def __init__(self, request_text, is_raw=False):
        """
        Build request from text representation. If is_raw is true - do not parse
        request, allow sending messages that break the RFC.
        """
        self.msg = request_text
        self.is_raw = is_raw
        if not self.is_raw:
            self.rfile = StringIO(request_text)
            self.raw_requestline = self.rfile.readline()
            self.error_code = self.error_message = None
            assert self.parse_request(), \
                "Cannot parse HTTP request: %s!" % self.error_message
            # parse_request doesnot save the body
            self.body = self.rfile.read()

    def send_error(self, code, message):
        """Dummy send error function. Just save the error."""
        self.error_code = code
        self.error_message = message

    def is_equal(self, other):
        """Assert that two requests are the same."""
        if self.is_raw or other.is_raw:
            raise framework.Error("Comparing raw requests is not supported!")

        return ((self.command == other.command)
                and (self.path == other.path)
                and (self.request_version == other.request_version)
                and (len(self.headers.headers) == len(other.headers.headers))
                and (set(self.headers.headers) == set(other.headers.headers))
                and (self.body == other.body))

    def __str__(self):
        if self.is_raw:
            return self.msg
        else:
            return ''.join(["Method:\t", self.command,
                            "URI:\t", self.path,
                            "Protocol:\t", self.request_version,
                            "Headers:\t", self.headers.headers.__str__(),
                            "Body:\t", self.body])
