from __future__ import print_function
import abc
from BaseHTTPServer import BaseHTTPRequestHandler
import httplib
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


class HttpMessage(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, message_text=None):
        self.msg = message_text
        self.headers = HeaderCollection()
        self.body = ''
        if message_text:
            stream = StringIO(self.msg)
            self.parse(stream)

    def parse(self, stream):
        self.parse_firstline(stream)
        self.parse_headers(stream)
        self.parse_body(stream)

    @abc.abstractmethod
    def parse_firstline(self, stream):
        pass

    def parse_headers(self, stream):
        self.headers = HeaderCollection().from_stream(stream)

    def parse_body(self, stream):
        self.body = stream.read()

    @abc.abstractmethod
    def __eq__(left, right):
        return (left.headers == right.headers) and (left.body == right.body)

    @abc.abstractmethod
    def __ne__(left, right):
        return not HttpMessage.__eq__(left, right)

    def __str__(self):
        return self.__dict__.__str__()

class Request(HttpMessage):

    def __init__(self, *args, **kwargs):
        self.method = None
        self.version = "HTTP/0.9" # default version.
        self.uri = None
        HttpMessage.__init__(self, *args, **kwargs)

    def parse_firstline(self, stream):
        requestline = stream.readline()
        words = requestline.rstrip('\r\n').split()
        if len(words) == 3:
            self.method, self.uri, self.version = words
        elif len(words) == 2:
            self.method, self.uri = words

    def __eq__(left, right):
        return ((left.method == right.method)
                and (left.version == right.version)
                and (left.uri == right.uri)
                and HttpMessage.__eq__(left, right))

    def __ne__(left, right):
        return not Request.__eq__(left, right)


class Response(HttpMessage):

    def __init__(self, *args, **kwargs):
        self.version = "HTTP/0.9" # default version.
        self.status = None  # Status-Code
        self.reason = None  # Reason-Phrase
        HttpMessage.__init__(self, *args, **kwargs)

    def parse_firstline(self, stream):
        statusline = stream.readline()
        words = statusline.rstrip('\r\n').split()
        if len(words) == 3:
            self.version, self.status, self.reason = words
        elif len(words) == 2:
            self.version, self.status = words

    def __eq__(left, right):
        return ((left.status == right.status)
                and (left.version == right.version)
                and (left.reason == right.reason)
                and HttpMessage.__eq__(left, right))

    def __ne__(left, right):
        return not Response.__eq__(left, right)
