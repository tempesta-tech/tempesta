from __future__ import print_function
import abc
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from . import framework


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HeaderCollection(object):
    """
    A collection class for HTTP Headers. This class combines aspects of a list
    and a dict. Lookup is always case-insenitive. A key can be added multiple
    times with different values, and all of those values will be kept.
    """

    def __init__(self, mapping=None, **kwargs):
        self.headers = []
        if mapping is not None:
            for k, v in mapping.iteritems():
                self.add(k, v)
        if kwargs is not None:
            for k, v in kwargs.iteritems():
                self.add(k, v)

    def __contains__(self, item):
        item = item.lower()
        for header in self.headers:
            if header[0].lower() == item:
                return True
        return False

    def __len__(self):
        return self.headers.__len__()

    def __getitem__(self, key):
        key = key.lower()
        for header in self.headers:
            if header[0].lower() == key:
                return header[1]

    def __setitem__(self, key, value):
        lower = key.lower()
        for i, header in enumerate(self.headers):
            if header[0].lower() == lower:
                headers[i] = (header[0], value)
                return
        else:
            self.add(key.lower(), value)

    def __delitem__(self, key):
        self.delete_all(name=key)

    def __iter__(self):
        return self.iterkeys()

    def add(self, name, value):
        self.headers.append((name.lower(), value,))

    def find_all(self, name):
        name = name.lower()
        for header in self.headers:
            if header[0].lower() == name:
                yield header[1]

    def delete_all(self, name):
        lower = name.lower()
        self.headers = [header for header in self.headers
                        if header[0].lower() != lower]

    def iterkeys(self):
        for header in self.headers:
            yield header[0]

    def itervalues(self):
        for header in self.headers:
            yield header[1]

    def iteritems(self):
        for header in self.headers:
            yield header

    def keys(self):
        return [key for key in self.iterkeys()]

    def values(self):
        return [value for value in self.itervalues()]

    def items(self):
        return self.headers

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

    @staticmethod
    def from_stream(rfile):
        headers = HeaderCollection()
        line = rfile.readline()
        while line and not (line == '\r\n' or line == '\n'):
            name, value = line.split(':', 1)
            name = name.strip()
            value = value.strip()
            line = rfile.readline()
            while line.startswith(' ') or line.startswith('\t'):
                # Continuation lines - see RFC 2616, section 4.2
                value += ' ' + line.strip()
                line = rfile.readline()
            headers.add(name, value)
        return headers

    def __eq__(left, right):
        return set(left.items()) == set(right.items())

    def __ne__(left, right):
        return not HeaderCollection.__eq__(left, right)

    def __str__(self):
        return self.headers.__str__()

    def __repr__(self):
        return self.headers.__repr__()
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
