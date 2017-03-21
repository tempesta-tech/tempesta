from __future__ import print_function
import re
from helpers import deproxy, tf_cfg
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

CHAIN_LENGTH = 20

def chains():
    chain = functional.base_message_chain()
    return [chain for i in range(CHAIN_LENGTH)]

def make_302(request):
    response = deproxy.Response(
                'HTTP/1.1 302 Found\r\n'
                'Content-Length: 0\r\n'
                'Location: http://%s%s\r\n'
                'Connection: keep-alive\r\n'
                '\r\n'
                % (tf_cfg.cfg.get('Tempesta', 'ip'), request.uri))
    return response

def make_502():
    response = deproxy.Response(
        'HTTP/1.1 502 Bad Gateway\r\n'
        'Content-Length: 0\r\n'
        'Connection: keep-alive\r\n'
        '\r\n')
    return response

class TesterIgnoreCookies(deproxy.Deproxy):
    """Tester helper. Emulate client that does not support cookies."""

    def __init__(self, *args, **kwargs):
         deproxy.Deproxy.__init__(self, *args, **kwargs)
         self.message_chains = chains()
         self.cookies = []

    def recieved_response(self, response):
        m = re.search(r'__tfw=([a-f0-9]+)', response.headers['Set-Cookie'])
        assert m, 'Set-Cookie header not found!'
        cookie = m.group(1)

        # Tempesta sent us a Cookie, and we were waiting for it.
        exp_resp = self.current_chain.response
        exp_resp.headers.delete_all('Set-Cookie')
        exp_resp.headers.add('Set-Cookie', response.headers['Set-Cookie'])
        exp_resp.update()

        # Client doesn't support cookies: Tempesta will generate new cookie for
        # each request.
        assert cookie not in self.cookies, \
            'Recieved non-uniquee cookie!'

        if exp_resp.status != '200':
            exp_resp.headers.delete_all('Date')
            exp_resp.headers.add('Date', response.headers['Date'])
            exp_resp.update()

        deproxy.Deproxy.recieved_response(self, response)


class TesterIgnoreEnforcedCookies(TesterIgnoreCookies):
    """Tester helper. Emulate client that does not support cookies, but
    Tempesta enforces cookies.
    """

    def __init__(self, *args, **kwargs):
         TesterIgnoreCookies.__init__(self, *args, **kwargs)
         self.message_chains[0].response = make_302(
            self.message_chains[0].request)
         self.message_chains[0].server_response = deproxy.Response()
         self.message_chains[0].fwd_request = deproxy.Request()


class TesterUseCookies(deproxy.Deproxy):
    """Tester helper. Emulate client that support cookies."""

    def __init__(self, *args, **kwargs):
         deproxy.Deproxy.__init__(self, *args, **kwargs)
         # The first message chain is unique.
         self.message_chains = [functional.base_message_chain()] + chains()
         self.cookie_parsed = False

    def recieved_response(self, response):
        if not self.cookie_parsed:
            m = re.search(r'__tfw=([a-f0-9]+)', response.headers['Set-Cookie'])
            assert m, 'Set-Cookie header not found!'
            cookie = m.group(1)

            # Tempesta sent us a Cookie, and we was waiting for it.
            exp_resp = self.current_chain.response
            exp_resp.headers.delete_all('Set-Cookie')
            exp_resp.headers.add('Set-Cookie', response.headers['Set-Cookie'])
            exp_resp.update()

            # All folowing requests must contain Cookie header
            for req in [self.message_chains[1].request,
                        self.message_chains[1].fwd_request]:
                req.headers.add('Cookie', ''.join(['__tfw=', cookie]))
                req.update()

            self.cookie_parsed = True

        exp_resp = self.current_chain.response
        if exp_resp.status != '200':
            exp_resp.headers.delete_all('Date')
            exp_resp.headers.add('Date', response.headers['Date'])
            exp_resp.update()

        deproxy.Deproxy.recieved_response(self, response)


class TesterUseEnforcedCookies(TesterUseCookies):
    """Tester helper. Emulate client that support cookies."""

    def __init__(self, *args, **kwargs):
         TesterUseCookies.__init__(self, *args, **kwargs)
         self.message_chains[0].response = make_302(
            self.message_chains[0].request)
         self.message_chains[0].server_response = deproxy.Response()
         self.message_chains[0].fwd_request = deproxy.Request()
