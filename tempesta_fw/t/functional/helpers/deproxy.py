from __future__ import print_function
import abc
import httplib
from StringIO import StringIO
import asyncore
import select
import socket
import sys
import time
from  BaseHTTPServer import BaseHTTPRequestHandler
from . import error, tf_cfg, tempesta


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

#-------------------------------------------------------------------------------
# Utils
#-------------------------------------------------------------------------------

class ParseError(Exception):
    pass

class IncompliteMessage(ParseError):
    pass


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
        self.headers.append((name, value,))

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
        return [key.lower() for key in self.iterkeys()]

    def values(self):
        return [value for value in self.itervalues()]

    def items(self):
        return self.headers

    def get(self, key, default=None):
        if key in self:
            return self[key]
        return default

    @staticmethod
    def from_stream(rfile, no_crlf=False):
        headers = HeaderCollection()
        line = rfile.readline()
        while not (line == '\r\n' or line == '\n'):
            if no_crlf and not line:
                break
            if not line or (line[-1] != '\n'):
                raise IncompliteMessage('Incomplite headers')
            line = line.rstrip('\r\n')
            try:
                name, value = line.split(':', 1)
            except:
                raise ParseError('Invalid header format')
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
        h_left = set([(hed.lower(), val) for hed, val in left.items()])
        h_right = set([(hed.lower(), val) for hed, val in right.items()])
        return h_left == h_right

    def __ne__(left, right):
        return not HeaderCollection.__eq__(left, right)

    def __str__(self):
        return ''.join(['%s: %s\r\n' % (hed, val) for hed, val in self.items()])

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
        self.trailer = HeaderCollection()
        self.body = ''
        self.version = "HTTP/0.9" # default version.
        if message_text:
            self.parse_text(message_text, body_parsing)

    def parse_text(self, message_text, body_parsing=True):
        self.body_parsing = body_parsing
        self.msg = message_text
        stream = StringIO(self.msg)
        self.__parse(stream)

    def __parse(self, stream):
        self.parse_firstline(stream)
        self.parse_headers(stream)
        self.body = ''
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
            else:
                error.bug('Not implemented!')
        elif self.body_parsing and 'Content-Length' in self.headers:
            length = int(self.headers['Content-Length'])
            self.read_sized_body(stream, length)
        else:
            self.body = stream.read()

    def read_chunked_body(self, stream):
        while True:
            line = stream.readline()
            self.body += line
            try:
                size = int(line.rstrip('\r\n'))
                assert size >= 0
                chunk = stream.readline()
                self.body += chunk

                assert len(chunk.rstrip('\r\n')) == size
                assert chunk[-1] == '\n'
                if size == 0:
                    break
            except:
                raise ParseError('Error in chuncked body')

        # Parsing trailer will eat last CRLF
        self.parse_trailer(stream)

    def read_sized_body(self, stream, size):
        if size == 0:
            return
        self.body = stream.read(size)
        # Remove CRLF
        line = stream.readline()
        if line.rstrip('\r\n'):
            raise ParseError('No CRLF after body.')
        if len(self.body) != size:
            raise ParseError(("Wrong body size: expect %d but got %d!"
                              % (size, len(self.body))))

    def parse_trailer(self, stream):
        self.trailer = HeaderCollection().from_stream(stream, no_crlf=True)

    @abc.abstractmethod
    def __eq__(left, right):
        return ((left.headers == right.headers) and
                (left.body == right.body) and
                (left.trailer == right.trailer))

    @abc.abstractmethod
    def __ne__(left, right):
        return not HttpMessage.__eq__(left, right)

    def __str__(self):
        return ''.join([str(self.headers), '\r\n', self.body, str(self.trailer)])

    def update(self, firstline):
        message = '\r\n'.join([firstline, str(self)])
        self.parse_text(message)

    @staticmethod
    def date_time_string(timestamp=None):
        """Return the current date and time formatted for a message header."""
        weekdayname = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        monthname = [None,
                     'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                     'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (
            weekdayname[wd], day, monthname[month], year, hh, mm, ss)
        return s

    @staticmethod
    def create(first_line, headers, date=False, srv_version=None, body=None):
        if date:
            date = ''.join(['Date: ', HttpMessage.date_time_string()])
            headers.append(date)
        if srv_version:
            version = ''.join(['Server: ', srv_version])
            headers.append(version)
        end = ['\r\n']
        if body != None:
            end = ['', body]
        return '\r\n'.join([first_line] + headers + end)


class Request(HttpMessage):

    methods = ['OPTIONS', 'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'TRACE',
               'CONNECT', 'PATCH']

    def __init__(self, *args, **kwargs):
        self.method = None
        self.uri = None
        HttpMessage.__init__(self, *args, **kwargs)

    def parse_firstline(self, stream):
        requestline = stream.readline()
        if requestline[-1] != '\n':
            raise IncompliteMessage('Incomplite request line!')

        words = requestline.rstrip('\r\n').split()
        if len(words) == 3:
            self.method, self.uri, self.version = words
        elif len(words) == 2:
            self.method, self.uri = words
        else:
            raise ParseError('Invalid request line!')
        if not self.method in self.methods:
            raise ParseError('Invalid request method!')

    def __eq__(left, right):
        return ((left.method == right.method)
                and (left.version == right.version)
                and (left.uri == right.uri)
                and HttpMessage.__eq__(left, right))

    def __ne__(left, right):
        return not Request.__eq__(left, right)

    def update(self):
        HttpMessage.update(self,
                           ' '.join([self.method, self.uri, self.version]))

    @staticmethod
    def create(method, headers, uri='/', version='HTTP/1.1', date=False,
               body=None):
        first_line = ' '.join([method, uri, version])
        msg = HttpMessage.create(first_line, headers, date=date, body=body)
        return Request(msg)


class Response(HttpMessage):

    def __init__(self, *args, **kwargs):
        self.status = None  # Status-Code
        self.reason = None  # Reason-Phrase
        HttpMessage.__init__(self, *args, **kwargs)

    def parse_firstline(self, stream):
        statusline = stream.readline()
        if statusline[-1] != '\n':
            raise IncompliteMessage('Incomplite Status line!')

        words = statusline.rstrip('\r\n').split()
        if len(words) >= 3:
            self.version, self.status = words[0:2]
            self.reason = ' '.join(words[2:])
        elif len(words) == 2:
            self.version, self.status = words
        else:
            raise ParseError('Invalid Status line!')
        try:
            status = int(self.status)
            assert status > 100 and status < 600
        except:
            raise ParseError('Invalid Status code!')

    def __eq__(left, right):
        return ((left.status == right.status)
                and (left.version == right.version)
                and (left.reason == right.reason)
                and HttpMessage.__eq__(left, right))

    def __ne__(left, right):
        return not Response.__eq__(left, right)

    def update(self):
        status = int(self.status)
        reason = reason = BaseHTTPRequestHandler.responses[status][0]
        HttpMessage.update(self,
                           ' '.join([self.version, self.status, reason]))

    @staticmethod
    def create(status, headers, version='HTTP/1.1', date=False,
               srv_version=None, body=None):
        reason = BaseHTTPRequestHandler.responses
        first_line = ' '.join([version, str(status), reason[status][0]])
        msg = HttpMessage.create(first_line, headers, date=date,
                                 srv_version=srv_version, body=body)
        return Response(msg)

#-------------------------------------------------------------------------------
# HTTP Client/Server
#-------------------------------------------------------------------------------
MAX_MESSAGE_SIZE = 65536

class Client(asyncore.dispatcher):

    def __init__(self, host=None, port=80):
        asyncore.dispatcher.__init__(self)
        self.request_buffer = ''
        self.response_buffer = ''
        self.tester = None
        if host is None:
            host = 'Tempesta'
        addr = tf_cfg.cfg.get(host, 'ip')
        tf_cfg.dbg(4, '\tDeproxy: Client: Conect to %s:%d.' % (addr, port))
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((addr, port))

    def clear(self):
        self.request_buffer = ''
        self.response_buffer = ''

    def set_request(self, request):
        if request:
            self.request_buffer = request.msg

    def set_tester(self, tester):
        self.tester = tester

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self):
        self.response_buffer += self.recv(MAX_MESSAGE_SIZE)
        if not self.response_buffer:
            return
        tf_cfg.dbg(4, '\tDeproxy: Client: Recieve response from Tempesta.')
        tf_cfg.dbg(5, self.response_buffer)
        try:
            response = Response(self.response_buffer)
        except IncompliteMessage:
            return
        except ParseError:
            tf_cfg.dbg(4, ('Deproxy: Client: Can\'t parse message\n'
                           '<<<<<\n%s>>>>>'
                           % self.response_buffer))
            raise
        if self.tester:
            self.tester.recieved_response(response)
        self.response_buffer = ''

    def writable(self):
        if not self.tester:
            return False
        return self.tester.is_srvs_ready() and (len(self.request_buffer) > 0)

    def handle_write(self):
        tf_cfg.dbg(4, '\tDeproxy: Client: Send request to server.')
        tf_cfg.dbg(5, self.request_buffer)
        sent = self.send(self.request_buffer)
        self.request_buffer = self.request_buffer[sent:]

    def handle_error(self):
        t, v, tb = sys.exc_info()
        error.bug('\tDeproxy: Client: %s' % v)


class ServerConnection(asyncore.dispatcher_with_send):

    def __init__(self, tester, server, sock=None, keep_alive=None):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.tester = tester
        self.server = server
        self.keep_alive = keep_alive
        self.responses_done = 0
        self.request_buffer = ''
        self.tester.register_srv_connection(self)
        tf_cfg.dbg(6, '\tDeproxy: SrvConnection: New server connection.')

    def handle_read(self):
        self.request_buffer += self.recv(MAX_MESSAGE_SIZE)
        try:
            request = Request(self.request_buffer)
        except IncompliteMessage:
            return
        except ParseError:
            tf_cfg.dbg(4, ('Deproxy: SrvConnection: Can\'t parse message\n'
                           '<<<<<\n%s>>>>>'
                           % self.request_buffer))
        # Hande will be called even if buffer is empty.
        if not self.request_buffer:
            return
        tf_cfg.dbg(4, '\tDeproxy: SrvConnection: Recieve request from Tempesta.')
        tf_cfg.dbg(5, self.request_buffer)
        if not self.tester:
            return
        response = self.tester.recieved_forwarded_request(request, self)
        self.request_buffer = ''
        if not response:
            return
        if response.msg:
            tf_cfg.dbg(4, '\tDeproxy: SrvConnection: Send response to Tempesta.')
            tf_cfg.dbg(5, response.msg)
            self.send(response.msg)
        else:
            tf_cfg.dbg(4, '\tDeproxy: SrvConnection: Try send invalid response.')
        if self.keep_alive:
            self.responses_done += 1
            if self.responses_done == self.keep_alive:
                self.handle_close()

    def handle_error(self):
        t, v, tb = sys.exc_info()
        error.bug('\tDeproxy: SrvConnection: %s' % v)

    def handle_close(self):
        tf_cfg.dbg(6, '\tDeproxy: SrvConnection: Close connection.')
        self.close()
        if self.tester:
            self.tester.remove_srv_connection(self)
        if self.server:
            try:
                self.server.connections.remove(self)
            except:
                pass


class Server(asyncore.dispatcher):

    def __init__(self, port, host=None, conns_n=None, keep_alive=None):
        asyncore.dispatcher.__init__(self)
        self.tester = None
        self.port = port
        self.connections = []
        if conns_n is None:
            conns_n = tempesta.server_conns_default()
        self.conns_n = conns_n
        self.keep_alive = keep_alive
        if host is None:
            host = 'Client'
        self.addr_str = tf_cfg.cfg.get('Client', 'ip')
        tf_cfg.dbg(4, '\tDeproxy: Server: Start on %s:%d.' % (self.addr_str, port))
        self.setup()

    def setup(self):
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((self.addr_str, self.port))
        self.listen(socket.SOMAXCONN)

    def restart(self):
        asyncore.dispatcher.__init__(self)
        self.tester.servers.append(self)
        self.setup()

    def stop(self):
        tf_cfg.dbg(4, '\tDeproxy: Server: Stop on %s:%d.' % (self.addr_str,
                                                             self.port))
        self.close()
        connections = [conn for conn in self.connections]
        for conn in connections:
            conn.handle_close()
        if self.tester:
            self.tester.servers.remove(self)

    def set_tester(self, tester):
        self.tester = tester

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            handler = ServerConnection(self.tester, server=self, sock=sock,
                                       keep_alive=self.keep_alive)
            self.connections.append(handler)
            assert len(self.connections) <= self.conns_n, \
                ('Too lot connections, expect %d, got %d'
                    & (self.conns_n, len(self.connections)))

    def active_conns_n(self):
        return len(self.connections)

    def handle_error(self):
        t, v, tb = sys.exc_info()
        error.bug('\tDeproxy: Server %s:%d: %s' % (self.addr_str, self.port, v))

    def handle_close(self):
        self.stop()


#-------------------------------------------------------------------------------
# Message Chain
#-------------------------------------------------------------------------------
TEST_CHAIN_TIMEOUT = 1.0

class MessageChain(object):

    def __init__(self, request, expected_response, forwarded_request=None,
                 server_response=None):
        # Request to be sent from Client.
        self.request = request
        # Response recieved on client.
        self.response = expected_response
        # Expexted request forwarded to server by Tempesta to server.
        self.fwd_request = forwarded_request if forwarded_request else Request()
        # Server response in reply to forwarded request.
        self.server_response = (
            server_response if expected_response else Response())

    def no_forward(self):
        # Expexted request forwarded to server by Tempesta to server.
        self.fwd_request = Request()
        # Server response in reply to forwarded request.
        self.server_response = Response()

    @staticmethod
    def empty():
        return MessageChain(Request(), Response())


class Deproxy(object):

    def __init__(self, message_chains, client, servers, register=True):
        self.message_chains = message_chains
        self.client = client
        self.servers = servers
        # Current chain of expected messages.
        self.current_chain = None
        # Current chain of recieved messages.
        self.recieved_chain = None
        # Timeout to wait for test completion.
        self.timeout = 1
        # Registered connections.
        self.srv_connections = []
        if register:
            self.register_tester()

    def register_tester(self):
        self.client.set_tester(self)
        for server in self.servers:
            server.set_tester(self)

    def loop(self, timeout=TEST_CHAIN_TIMEOUT):
        """Poll for socket events no more than `timeout` seconds."""
        try:
            eta = time.time() + timeout
            map =  asyncore.socket_map

            if hasattr(select, 'poll'):
                poll_fun = asyncore.poll2
            else:
                poll_fun = asyncore.poll

            while (eta > time.time()) and map:
                poll_fun(min(self.timeout, timeout), map)
        except asyncore.ExitNow:
            pass

    def run(self):
        for self.current_chain in self.message_chains:
            self.recieved_chain = MessageChain.empty()
            self.client.clear()
            self.client.set_request(self.current_chain.request)
            self.loop()
            self.check_expectations()

    def check_expectations(self):
        for message in ['response', 'fwd_request']:
            expected = getattr(self.current_chain, message)
            recieved = getattr(self.recieved_chain, message)
            assert expected == recieved, \
                ("Recieved message (%s) does not suit expected one!\n\n"
                 "\tRecieved:\n<<<<<|\n%s|>>>>>\n"
                 "\tExpected:\n<<<<<|\n%s|>>>>>\n"
                 % (message, recieved.msg, expected.msg))

    def recieved_response(self, response):
        """Client recieved response for its request."""
        self.recieved_chain.response = response
        raise asyncore.ExitNow

    def recieved_forwarded_request(self, request, connection):
        self.recieved_chain.fwd_request = request
        return self.current_chain.server_response

    def register_srv_connection(self, connection):
        assert connection.server in self.servers, \
            'Register connection, which comes from not registred server!'
        self.srv_connections.append(connection)

    def remove_srv_connection(self, connection):
        # Normaly we have the connection in the list, but do not crash test
        # framework if that is not true.
        try:
            self.srv_connections.remove(connection)
        except:
            pass

    def is_srvs_ready(self):
        expected_conns_n = sum([s.conns_n for s in self.servers])
        assert len(self.srv_connections) <= expected_conns_n, \
            'Registered more connections that must be!.'
        return expected_conns_n == len(self.srv_connections)

    def close_all(self):
        self.client.handle_close()
        servers = [server for server in self.servers]
        for server in servers:
            server.handle_close()
