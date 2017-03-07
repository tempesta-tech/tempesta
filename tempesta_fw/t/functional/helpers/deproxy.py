from __future__ import print_function
import abc
import httplib
from StringIO import StringIO
import asyncore
import socket
from . import error, tf_cfg


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

#-------------------------------------------------------------------------------
# Utils
#-------------------------------------------------------------------------------

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
        return str(self.headers)

    def __repr__(self):
        return repr(self.headers)


#-------------------------------------------------------------------------------
# HTTP Messages
#-------------------------------------------------------------------------------

class HttpMessage(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, message_text=None, body_parsing=True):
        self.msg = ''
        self.body_parsing = True
        self.headers = HeaderCollection()
        self.body = ''
        if message_text:
            self.parse_text(message_text, body_parsing)

    def parse_text(self, message_text, body_parsing=True):
        self.body_parsing = body_parsing
        self.msg = message_text
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
        if self.body_parsing and 'Transfer-Encoding' in self.headers:
            chunked = False
            enc = self.headers['Transfer-Encoding']
            option = enc.split(',')[-1] # take the last option

            if option.strip().lower() == 'chunked':
                self.read_chunked_body(stream)
                # TODO: read trailer.
            else:
                error.bug('Not implemented!')
        elif self.body_parsing and 'Content-Length' in self.headers:
            length = int(self.headers['Content-Length'])
            self.read_sized_body(stream, length)
        else:
            self.body = stream.read()

    def read_chunked_body(self, stream):
        line = stream.readline()
        while line and not (line == '\r\n' or line == '\n'):
            self.body += line
            line = stream.readline()

    def read_sized_body(self, stream, size):
        self.body = stream.read(size)
        # Remove CRLF
        stream.readline()
        assert (len(self.body) == size), \
            "Wrong body size: expect %d but got %d!" % (size, len(self.body))

    @abc.abstractmethod
    def __eq__(left, right):
        return (left.headers == right.headers) and (left.body == right.body)

    @abc.abstractmethod
    def __ne__(left, right):
        return not HttpMessage.__eq__(left, right)

    def __str__(self):
        return str(self.__dict__)


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

#-------------------------------------------------------------------------------
# HTTP Client/Server
#-------------------------------------------------------------------------------
MAX_MESSAGE_SIZE = 65536

class Client(asyncore.dispatcher):

    def __init__(self, host=None, port=80):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        if host == None:
            self.host = tf_cfg.cfg.get('Client', 'hostname')
        self.connect((host, port))
        self.request_bufer = ''
        self.responce_bufer = ''
        self.tester = None

    def clear(self):
        self.request_bufer = ''
        self.responce_bufer = ''

    def set_request(self, request):
        self.request_bufer = request.msg

    def set_tester(self, tester):
        self.tester = tester

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self):
        buffer += self.recv(MAX_MESSAGE_SIZE)
        response = Response(buffer)
        tester.recieved_response(response)

    def writable(self):
        return (len(self.bufer) > 0)

    def handle_write(self):
        sent = self.send(self.buffer)
        self.buffer = self.buffer[sent:]


class ServerConnection(asyncore.dispatcher_with_send):

    def __init__(self, tester, server, sock=None):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.tester = tester
        self.server = server

    def handle_read(self):
        buffer = self.recv(MAX_MESSAGE_SIZE)
        request = Request(buffer)
        response = tester.recieved_forwarded_request(request, self)
        if response.msg:
            self.send(response.msg)

class Server(asyncore.dispatcher):

    def __init__(self, id, port, host=None):
        asyncore.dispatcher.__init__(self)
        self.id = id
        self.tester = None
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        if host == None:
            self.host = tf_cfg.cfg.get('Client', 'hostname')
        self.bind((host, port))
        self.listen(socket.SOMAXCON)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            tf_cfg.dbg(4, 'Incoming connection from %s' % repr(addr))
            handler = EchoHandler(sock)


#-------------------------------------------------------------------------------
# Message Chain
#-------------------------------------------------------------------------------
TEST_CHAIN_TIMEOUT = 1

class MessageChain(object):

    def __init__(self, request, expected_response, forwarded_request=None,
                 server_response=None):
        # Request to be sent from Client.
        self.request = request
        # Response recieved on client.
        self.response = expected_response if expected_response else Response()
        # Expexted request forwarded to server by Tempesta to server.
        self.fwd_request = forwarded_request if forwarded_request else Request()
        # Server response in reply to forwarded request.
        self.server_response = server_response

class Deproxy(object):

    def __init__(self, message_chains, client, servers):
        self.message_chains = message_chains
        self.client = client
        self.servers = servers
        # Current chain of expected messages
        self.current_chain = None
        # Current chain of recieved messages
        self.recieved_chain = None
        self.timeout = TEST_CHAIN_TIMEOUT
        client.set_tester(self)
        for server in servers:
            server.set_tester(self)

    def run(self):
        for self.current_chain in self.message_chains:
            self.recieved_chain = MessageChain(None, None)
            self.client.clear()
            self.client.set_request(self.current_chain.request)
            try:
                asyncore.loop(timeout=self.timeout)
            except asyncore.ExitNow:
                pass
            self.check_expectations()

    def check_expectations(self):
        for message in ['response', 'fwd_request']:
            expected = get_attr(self.current_chain, message)
            recieved = get_attr(self.recieved_chain, message)
            assert expected == recieved \
                ("Recieved message does not suit expected one!\n"
                 "\tRecieved:\t%s\n\tExpected:\t%s\n" % (expected, recieved))

    def recieved_response(self, response, client):
        """Client recieved response for its request."""
        recieved_chain.response = response
        raise asyncore.ExitNow

    def recieved_forwarded_request(self, request, connection):
        recieved_chain.fwd_request = request
        return self.current_chain.server_response
