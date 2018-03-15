from __future__ import print_function
import abc
from StringIO import StringIO
import asyncore
import select
import socket
import sys
import time
import calendar # for calendar.timegm()
from  BaseHTTPServer import BaseHTTPRequestHandler
from . import error, tf_cfg, tempesta, stateful


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
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
    and a dict. Lookup is always case-insensitive. A key can be added multiple
    times with different values, and all of those values will be kept.
    """

    def __init__(self, mapping=None, **kwargs):
        self.headers = []
        self.is_expected = False
        self.expected_time_delta = None
        if mapping is not None:
            for k, v in mapping.iteritems():
                self.add(k, v)
        if kwargs is not None:
            for k, v in kwargs.iteritems():
                self.add(k, v)

    def set_expected(self, expected_time_delta = 0):
        self.is_expected = True
        self.expected_time_delta = expected_time_delta

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
                self.headers[i] = (header[0], value)
                return
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

    def _as_dict_lower(self):
        ret = {}
        for hed, val in self.items():
            ret.setdefault(hed.lower(), []).append(val)
        return ret

    def _has_good_date(self):
        return len(self.headers.get('date', [])) == 1

    _disable_report_wrong_is_expected = False

    def _report_wrong_is_expected(self, other):
            if not HeaderCollection._disable_report_wrong_is_expected:
                error.bug("HeaderCollection: comparing is_expected=(%s, %s)\n" %
                          (self.is_expected, other.is_expected))

    def __eq__(self, other):
        h_self = self._as_dict_lower()
        h_other = other._as_dict_lower()

        if self.is_expected == other.is_expected:
            self._report_wrong_is_expected(other)
        else:
            if self.is_expected:
                h_expected, h_received = h_self, h_other
            else:
                h_expected, h_received = h_other, h_self

            # Special-case "Date: " header if both headers have it and it looks OK
            # (i. e. not duplicated):
            if (len(h_expected.get('date', [])) == 1 and
                len(h_received.get('date', [])) == 1):
                ts_expected = HttpMessage.parse_date_time_string(h_expected.pop('date')[0])
                ts_received = HttpMessage.parse_date_time_string(h_received.pop('date')[0])
                if not (ts_received >= ts_expected and
                        ts_received <= ts_expected + self.expected_time_delta):
                    return False

            # Special-case "Age:" header if both headers must have it:
            if (len(h_expected.get('age', [])) == 1 and
                len(h_received.get('age', [])) == 1):
                age_expected = int(h_expected.pop('age')[0])
                age_received = int(h_received.pop('age')[0])
                if not (age_expected <= age_received):
                    return False

        return h_self == h_other

    def __ne__(self, other):
        return not HeaderCollection.__eq__(self, other)

    def __str__(self):
        return ''.join(['%s: %s\r\n' % (hed, val) for hed, val in self.items()])

    def __repr__(self):
        return repr(self.headers)


#-------------------------------------------------------------------------------
# HTTP Messages
#-------------------------------------------------------------------------------

class HttpMessage(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, message_text=None, body_parsing=True, method="GET"):
        self.msg = ''
        self.method = method
        self.body_parsing = True
        self.headers = HeaderCollection()
        self.trailer = HeaderCollection()
        self.body = ''
        self.version = "HTTP/0.9" # default version.
        if message_text:
            self.parse_text(message_text, body_parsing)

    def parse_text(self, message_text, body_parsing=True):
        self.body_parsing = body_parsing
        stream = StringIO(message_text)
        self.__parse(stream)
        self.build_message()

    def __parse(self, stream):
        self.parse_firstline(stream)
        self.parse_headers(stream)
        self.body = ''
        self.parse_body(stream)

    def build_message(self):
        self.msg = str(self)

    @abc.abstractmethod
    def parse_firstline(self, stream):
        pass

    @abc.abstractmethod
    def parse_body(self, stream):
        pass

    def get_firstline(self):
        return ''

    def parse_headers(self, stream):
        self.headers = HeaderCollection.from_stream(stream)

    def read_encoded_body(self, stream):
        """ RFC 7230. 3.3.3 #3 """
        enc = self.headers['Transfer-Encoding']
        option = enc.split(',')[-1] # take the last option

        if option.strip().lower() == 'chunked':
            self.read_chunked_body(stream)
        else:
            error.bug('Not implemented!')

    def read_rest_body(self, stream):
        """ RFC 7230. 3.3.3 #7 """
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
                raise ParseError('Error in chunked body')

        # Parsing trailer will eat last CRLF
        self.parse_trailer(stream)

    def read_sized_body(self, stream):
        """ RFC 7230. 3.3.3 #5 """
        size = int(self.headers['Content-Length'])

        self.body = stream.read(size)
        if len(self.body) != size:
            raise ParseError(("Wrong body size: expect %d but got %d!"
                              % (size, len(self.body))))

    def parse_trailer(self, stream):
        self.trailer = HeaderCollection.from_stream(stream, no_crlf=True)

    @abc.abstractmethod
    def __eq__(self, other):
        return ((self.headers == other.headers) and
                (self.body == other.body) and
                (self.trailer == other.trailer))

    @abc.abstractmethod
    def __ne__(self, other):
        return not HttpMessage.__eq__(self, other)

    def __str__(self):
        return ''.join([self.get_firstline(), '\r\n', str(self.headers), '\r\n',
                        self.body, str(self.trailer)])

    def update(self):
        self.parse_text(str(self))

    def set_expected(self, *args, **kwargs):
        for obj in [self.headers, self.trailer]:
            obj.set_expected(*args, **kwargs)

    @staticmethod
    def date_time_string(timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        struct_time = time.gmtime(timestamp)
        s = time.strftime("%a, %02d %3b %4Y %02H:%02M:%02S GMT", struct_time)
        return s

    @staticmethod
    def parse_date_time_string(s):
        """Return a timestamp corresponding to the given Date: header."""
        struct_time = time.strptime(s, "%a, %d %b %Y %H:%M:%S GMT")
        timestamp = calendar.timegm(struct_time)
        return timestamp

    @staticmethod
    def create(first_line, headers, date=None, srv_version=None, body=None):
        if date:
            date = ''.join(['Date: ', date])
            headers.append(date)
        if srv_version:
            version = ''.join(['Server: ', srv_version])
            headers.append(version)
        end = ['\r\n']
        if body != None:
            end = ['', body]
        return '\r\n'.join([first_line] + headers + end)


class Request(HttpMessage):

    # All methods registered in IANA.
    # https://www.iana.org/assignments/http-methods/http-methods.xhtml
    methods = ['ACL', 'BASELINE-CONTROL', 'BIND', 'CHECKIN', 'CHECKOUT',
               'CONNECT', 'COPY', 'DELETE', 'GET', 'HEAD', 'LABEL', 'LINK',
               'LOCK', 'MERGE', 'MKACTIVITY', 'MKCALENDAR', 'MKCOL',
               'MKREDIRECTREF', 'MKWORKSPACE', 'MOVE', 'OPTIONS', 'ORDERPATCH',
               'PATCH', 'POST', 'PRI', 'PROPFIND', 'PROPPATCH', 'PUT', 'REBIND',
               'REPORT', 'SEARCH', 'TRACE', 'UNBIND', 'UNCHECKOUT', 'UNLINK',
               'UNLOCK', 'UPDATE', 'UPDATEREDIRECTREF', 'VERSION-CONTROL',
               # Not RFC methods:
               'PURGE']

    def __init__(self, *args, **kwargs):
        self.method = None
        self.uri = None
        HttpMessage.__init__(self, *args, **kwargs)

    def parse_firstline(self, stream):
        requestline = stream.readline()
        if requestline[-1] != '\n':
            raise IncompliteMessage('Incomplete request line!')

        words = requestline.rstrip('\r\n').split()
        if len(words) == 3:
            self.method, self.uri, self.version = words
        elif len(words) == 2:
            self.method, self.uri = words
        else:
            raise ParseError('Invalid request line!')
        if not self.method in self.methods:
            raise ParseError('Invalid request method!')

    def get_firstline(self):
        return ' '.join([self.method, self.uri, self.version])

    def parse_body(self, stream):
        """ RFC 7230 3.3.3 """
        # 3.3.3 3
        if 'Transfer-Encoding' in self.headers:
            self.read_encoded_body(stream)
            return
        # 3.3.3 5
        if 'Content-Length' in self.headers:
            self.read_sized_body(stream)
            return
        # 3.3.3 6
        self.body = ''

    def __eq__(self, other):
        return ((self.method == other.method)
                and (self.version == other.version)
                and (self.uri == other.uri)
                and HttpMessage.__eq__(self, other))

    def __ne__(self, other):
        return not Request.__eq__(self, other)

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
            raise IncompliteMessage('Incomplete Status line!')

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

    def parse_body(self, stream):
        """ RFC 7230 3.3.3 """
        # 3.3.3 1
        if self.method == "HEAD":
            return
        code = int(self.status)
        if code >= 100 and code <= 199 or \
            code == 204 or code == 304:
            return
        # 3.3.3 2
        if self.method == "CONNECT" and code >= 200 and code <= 299:
            error.bug('Not implemented!')
            return
        # 3.3.3 3
        if 'Transfer-Encoding' in self.headers:
            self.read_encoded_body(stream)
            return
        # TODO: check 3.3.3 4
        # 3.3.3 5
        if 'Content-Length' in self.headers:
            self.read_sized_body(stream)
            return
        # 3.3.3 7
        self.read_rest_body(stream)

    def get_firstline(self):
        status = int(self.status)
        reason = BaseHTTPRequestHandler.responses[status][0]
        return ' '.join([self.version, self.status, reason])

    def __eq__(self, other):
        return ((self.status == other.status)
                and (self.version == other.version)
                and (self.reason == other.reason)
                and HttpMessage.__eq__(self, other))

    def __ne__(self, other):
        return not Response.__eq__(self, other)

    @staticmethod
    def create(status, headers, version='HTTP/1.1', date=False,
               srv_version=None, body=None, method='GET'):
        reason = BaseHTTPRequestHandler.responses
        first_line = ' '.join([version, str(status), reason[status][0]])
        msg = HttpMessage.create(first_line, headers, date=date,
                                 srv_version=srv_version, body=body)
        return Response(msg, method=method)

#-------------------------------------------------------------------------------
# HTTP Client/Server
#-------------------------------------------------------------------------------
MAX_MESSAGE_SIZE = 65536

class Client(asyncore.dispatcher, stateful.Stateful):

    def __init__(self, addr=None, host='Tempesta', port=80):
        asyncore.dispatcher.__init__(self)
        self.request = None
        self.request_buffer = ''
        self.response_buffer = ''
        self.tester = None
        if addr is None:
            addr = tf_cfg.cfg.get(host, 'ip')
        tf_cfg.dbg(4, '\tDeproxy: Client: Connect to %s:%d.' % (addr, port))
        self.addr = addr
        self.port = port
        self.stop_procedures = [self.__stop_client]
        self.orig_addr = ''

    def __stop_client(self):
        tf_cfg.dbg(4, '\tStop deproxy client')
        self.close()
        self.addr = self.orig_addr

    def run_start(self):
        self.orig_addr = self.addr
        tf_cfg.dbg(3, '\tStarting deproxy client')
        tf_cfg.dbg(4, '\tDeproxy: Client: Connect to %s:%d.' % (self.addr, self.port))
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((self.addr, self.port))

    def clear(self):
        self.request_buffer = ''

    def set_request(self, message_chain):
        if message_chain:
            self.request = message_chain.request
            self.request_buffer = message_chain.request.msg

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
        tf_cfg.dbg(4, '\tDeproxy: Client: Receive response from Tempesta.')
        tf_cfg.dbg(5, self.response_buffer)
        try:
            response = Response(self.response_buffer,
                                method=self.request.method)
            self.response_buffer = self.response_buffer[len(response.msg):]
        except IncompliteMessage:
            return
        except ParseError:
            tf_cfg.dbg(4, ('Deproxy: Client: Can\'t parse message\n'
                           '<<<<<\n%s>>>>>'
                           % self.response_buffer))
            raise
        if len(self.response_buffer) > 0:
            # TODO: take care about pipelined case
            raise ParseError('Garbage after response end:\n```\n%s\n```\n' % \
                             self.response_buffer)
        if self.tester:
            self.tester.recieved_response(response)
        self.response_buffer = ''

    def writable(self):
        if not self.tester:
            return False
        return self.tester.is_srvs_ready() and (len(self.request_buffer) > 0)

    def handle_write(self):
        tf_cfg.dbg(4, '\tDeproxy: Client: Send request to Tempesta.')
        tf_cfg.dbg(5, self.request_buffer)
        sent = self.send(self.request_buffer)
        self.request_buffer = self.request_buffer[sent:]

    def handle_error(self):
        _, v, _ = sys.exc_info()
        if type(v) == ParseError or type(v) == AssertionError:
            raise v
        else:
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
        # Handler will be called even if buffer is empty.
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
        self.send_response(response)

    def send_response(self, response):
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
        _, v, _ = sys.exc_info()
        error.bug('\tDeproxy: SrvConnection: %s' % v)

    def handle_close(self):
        tf_cfg.dbg(6, '\tDeproxy: SrvConnection: Close connection.')
        self.close()
        if self.tester:
            self.tester.remove_srv_connection(self)
        if self.server:
            try:
                self.server.connections.remove(self)
            except ValueError:
                pass


class Server(asyncore.dispatcher, stateful.Stateful):

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
        self.ip = tf_cfg.cfg.get('Client', 'ip')
        self.stop_procedures = [self.__stop_server]

    def run_start(self):
        tf_cfg.dbg(3, '\tDeproxy: Server: Start on %s:%d.' % (self.ip, self.port))
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((self.ip, self.port))
        self.listen(socket.SOMAXCONN)

    def __stop_server(self):
        tf_cfg.dbg(3, '\tDeproxy: Server: Stop on %s:%d.' % (self.ip,
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
            sock, _ = pair
            handler = ServerConnection(self.tester, server=self, sock=sock,
                                       keep_alive=self.keep_alive)
            self.connections.append(handler)
            assert len(self.connections) <= self.conns_n, \
                ('Too lot connections, expect %d, got %d'
                 % (self.conns_n, len(self.connections)))

    def handle_read_event(self):
        asyncore.dispatcher.handle_read_event(self)

    def active_conns_n(self):
        return len(self.connections)

    def handle_error(self):
        _, v, _ = sys.exc_info()
        if type(v) == AssertionError:
            raise v
        else:
            raise  Exception('\tDeproxy: Server %s:%d: %s' % \
             (self.ip, self.port, type(v)))

    def handle_close(self):
        self.stop()


#-------------------------------------------------------------------------------
# Message Chain
#-------------------------------------------------------------------------------
TEST_CHAIN_TIMEOUT = 5

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
        self.server_response = server_response if server_response else Response()

    @staticmethod
    def empty():
        return MessageChain(Request(), Response())


class Deproxy(stateful.Stateful):

    def __init__(self, client, servers, register=True, message_chains=None):
        self.message_chains = message_chains
        self.client = client
        self.servers = servers
        # Current chain of expected messages.
        self.current_chain = None
        # Current chain of recieved messages.
        self.recieved_chain = None
        # Default per-message-chain loop timeout.
        self.timeout = TEST_CHAIN_TIMEOUT
        # Registered connections.
        self.srv_connections = []
        if register:
            self.register_tester()
        self.stop_procedures = [self.__stop_deproxy]

    def __stop_deproxy(self):
        tf_cfg.dbg(3, '\tStopping deproxy tester')

    def run_start(self):
        tf_cfg.dbg(3, '\tStarting deproxy tester')

    def register_tester(self):
        self.client.set_tester(self)
        for server in self.servers:
            server.set_tester(self)

    def loop(self, timeout=None):
        """Poll for socket events no more than `self.timeout` or `timeout` seconds."""
        if timeout is not None:
            timeout = min(timeout, self.timeout)
        else:
            timeout = self.timeout

        try:
            eta = time.time() + timeout
            s_map = asyncore.socket_map

            if hasattr(select, 'poll'):
                poll_fun = asyncore.poll2
            else:
                poll_fun = asyncore.poll

            while (eta > time.time()) and s_map:
                poll_fun(eta - time.time(), s_map)
        except asyncore.ExitNow:
            pass

    def run(self):
        if self.message_chains is None:
            return
        for self.current_chain in self.message_chains:
            self.recieved_chain = MessageChain.empty()
            self.client.clear()
            self.client.set_request(self.current_chain)
            self.loop()
            self.check_expectations()

    def check_expectations(self):
        for message in ['response', 'fwd_request']:
            expected = getattr(self.current_chain, message)
            recieved = getattr(self.recieved_chain, message)
            expected.set_expected(expected_time_delta=self.timeout)
            assert expected == recieved, \
                ("Received message (%s) does not suit expected one!\n\n"
                 "\tReceieved:\n<<<<<|\n%s|>>>>>\n"
                 "\tExpected:\n<<<<<|\n%s|>>>>>\n"
                 % (message, recieved.msg, expected.msg))

    def recieved_response(self, response):
        """Client received response for its request."""
        self.recieved_chain.response = response
        raise asyncore.ExitNow

    def recieved_forwarded_request(self, request, connection=None):
        self.recieved_chain.fwd_request = request
        return self.current_chain.server_response

    def register_srv_connection(self, connection):
        assert connection.server in self.servers, \
            'Register connection, which comes from not registered server!'
        self.srv_connections.append(connection)

    def remove_srv_connection(self, connection):
        # Normally we have the connection in the list, but do not crash test
        # framework if that is not true.
        try:
            self.srv_connections.remove(connection)
        except ValueError:
            pass

    def is_srvs_ready(self):
        expected_conns_n = sum([s.conns_n for s in self.servers])
        assert len(self.srv_connections) <= expected_conns_n, \
            'Registered more connections that must be!.'
        return expected_conns_n == len(self.srv_connections)

def finish_all_deproxy():
    asyncore.close_all()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
