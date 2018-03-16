""" Testing for missing or wrong body length in response """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import unittest
import body_generator
import os

from . import tester

from testers import functional
from helpers import tf_cfg, control, tempesta, remote, deproxy, chains

def resp_body_length(base, length):
    """ Generate chain with missing or specified body length """
    for msg in ['response', 'server_response']:
        field = getattr(base, msg)
        field.headers.delete_all('Content-Length')
        if length != None:
            actual_len = len(field.body)
            if msg == 'response' and actual_len < length:
                field.headers.add('Content-Length', '%i' % actual_len)
            else:
                field.headers.add('Content-Length', '%i' % length)

    base.response.update()
    base.server_response.build_message()
    return base

def generate_chain_200(method='GET', response_body=""):
    base = chains.base(method=method)
    base.response.status = "200"
    base.response.body = response_body
    base.response.headers['Content-Length'] = len(response_body)
    base.server_response.status = "200"
    base.server_response.body = response_body
    base.server_response.headers['Content-Length'] = len(response_body)
    base.response.update()
    base.server_response.update()
    return base

def generate_chain_204(method='GET'):
    base = chains.base(method=method)
    base.response.status = "204" # it's default, but for explicity
    base.response.body = ""
    base.server_response.status = "204"
    base.server_response.body = ""
    return base

class InvalidResponseServer(deproxy.Server):

    def __stop_server(self):
        deproxy.Server.__stop_server(self)
        assert len(self.connections) <= self.conns_n, \
                ('Too lot connections, expect %d, got %d'
                 % (self.conns_n, len(self.connections)))

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, _ = pair
            handler = deproxy.ServerConnection(self.tester, server=self,
                                               sock=sock,
                                               keep_alive=self.keep_alive)
            self.connections.append(handler)

class TesterCorrectEmptyBodyLength(deproxy.Deproxy):
    """ Tester """
    def create_base(self):
        base = generate_chain_200(method='GET')
        return (base, len(base.response.body))

    def recieved_response(self, response):
        """Client received response for its request."""
        self.recieved_chain.response = response

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = self.create_base()
        self.message_chains = [resp_body_length(base[0], base[1])]
        self.cookies = []

class TesterCorrectBodyLength(deproxy.Deproxy):
    """ Tester """
    def create_base(self):
        base = generate_chain_200(method='GET', response_body="abcd")
        return (base, len(base.response.body))

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = self.create_base()
        self.message_chains = [resp_body_length(base[0], base[1])]
        self.cookies = []

class TesterMissingEmptyBodyLength(deproxy.Deproxy):
    """ Tester """
    reply_body = ""

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        chain = generate_chain_200(method='GET', response_body=self.reply_body)
        chain.server_response.headers.delete_all('Content-Length')
        chain.server_response.update()
        self.message_chains = [chain]
        self.cookies = []

class TesterMissingBodyLength(TesterMissingEmptyBodyLength):
    """ Tester """
    reply_body = "abcdefgh"

class TesterSmallBodyLength(TesterCorrectBodyLength):
    """ Tester """
    def create_base(self):
        base = generate_chain_200(method='GET', response_body="abcdefgh")
        return (base, len(base.response.body) - 1)

class TesterForbiddenZeroBodyLength(deproxy.Deproxy):
    """ Tester """
    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = self.create_base()
        base[0].server_response.headers.delete_all('Content-Length')
        base[0].server_response.headers.add('Content-Length', "%i" % base[1])
        base[0].server_response.build_message()

        base[0].response = chains.make_502_expected()

        self.message_chains = [base[0]]
        self.cookies = []

    def create_base(self):
        base = generate_chain_204(method='GET')
        return (base, 0)

class TesterForbiddenPositiveBodyLength(TesterForbiddenZeroBodyLength):
    """ Tester """
    def create_base(self):
        base = generate_chain_204(method='GET')
        return (base, 1)

class TesterDuplicateBodyLength(deproxy.Deproxy):
    """ Tester """
    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = self.create_base()
        cl = base[0].server_response.headers['Content-Length']
        base[0].server_response.headers.add('Content-Length', cl)
        base[0].server_response.build_message()

        base[0].response = chains.make_502_expected()

        self.message_chains = [base[0]]
        self.cookies = []

    def create_base(self):
        base = generate_chain_204(method='GET')
        return (base, 0)

class TesterSecondBodyLength(deproxy.Deproxy):
    """ Tester """
    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = self.create_base()
        cl = base[0].server_response.headers['Content-Length']
        length = int(cl)
        base[0].server_response.headers.add('Content-Length',
                                            "%i" % (length - 1))
        base[0].server_response.build_message()

        base[0].response = chains.make_502_expected()

        self.message_chains = [base[0]]
        self.cookies = []

    def create_base(self):
        base = generate_chain_204(method='GET')
        return (base, 0)

class TesterInvalidBodyLength(deproxy.Deproxy):
    """ Tester """
    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = self.create_base()
        base[0].server_response.headers['Content-Length'] = "invalid"
        base[0].server_response.build_message()

        base[0].response = chains.make_502_expected()

        self.message_chains = [base[0]]
        self.cookies = []

    def create_base(self):
        base = generate_chain_204(method='GET')
        return (base, 0)

class ResponseCorrectEmptyBodyLength(functional.FunctionalTest):
    """ Correct body length """
    config = 'cache 0;\nblock_action error reply;\nblock_action attack reply;\n'

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [InvalidResponseServer(port=port)]

    def create_client(self):
        self.client = deproxy.Client()

    def create_tester(self):
        self.tester = TesterCorrectEmptyBodyLength(self.client, self.servers)

    def test(self):
        """ Test """
        self.generic_test_routine(self.config, [])

class ResponseCorrectBodyLength(ResponseCorrectEmptyBodyLength):
    """ Correct body length """

    def create_tester(self):
        self.tester = TesterCorrectBodyLength(self.client, self.servers)

class ResponseMissingEmptyBodyLength(ResponseCorrectEmptyBodyLength):
    """ Missing body length """

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port, keep_alive=1)]

    def create_tester(self):
        self.tester = TesterMissingEmptyBodyLength(self.client, self.servers)

class ResponseMissingBodyLength(ResponseMissingEmptyBodyLength):
    """ Missing body length """

    def create_tester(self):
        self.tester = TesterMissingBodyLength(self.client, self.servers)

class ResponseSmallBodyLength(ResponseCorrectEmptyBodyLength):
    """ Small body length """

    def create_tester(self):
        self.tester = TesterSmallBodyLength(self.client, self.servers)

    def assert_tempesta(self):
        msg = 'Tempesta have errors in processing HTTP %s.'
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 0,
                         msg=(msg % 'responses'))
        self.assertEqual(self.tempesta.stats.cl_msg_other_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_other_errors, 1,
                         msg=(msg % 'responses'))

class ResponseForbiddenZeroBodyLength(ResponseCorrectEmptyBodyLength):
    """ Forbidden body length """

    def create_tester(self):
        self.tester = TesterForbiddenZeroBodyLength(self.client, self.servers)

    def assert_tempesta(self):
        msg = 'Tempesta have errors in processing HTTP %s.'
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 1,
                         msg=(msg % 'responses'))
        self.assertEqual(self.tempesta.stats.cl_msg_other_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_other_errors, 0,
                         msg=(msg % 'responses'))


class ResponseForbiddenPositiveBodyLength(ResponseForbiddenZeroBodyLength):
    """ Forbidden body length """

    def create_tester(self):
        self.tester = TesterForbiddenPositiveBodyLength(self.client,
                                                        self.servers)

class ResponseDuplicateBodyLength(ResponseCorrectEmptyBodyLength):
    def create_tester(self):
        self.tester = TesterDuplicateBodyLength(self.client, self.servers)

    def assert_tempesta(self):
        msg = 'Tempesta have errors in processing HTTP %s.'
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 1,
                         msg=(msg % 'responses'))
        self.assertEqual(self.tempesta.stats.cl_msg_other_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_other_errors, 0,
                         msg=(msg % 'responses'))

class ResponseSecondBodyLength(ResponseDuplicateBodyLength):
    def create_tester(self):
        self.tester = TesterSecondBodyLength(self.client, self.servers)

class ResponseInvalidBodyLength(ResponseDuplicateBodyLength):
    def create_tester(self):
        self.tester = TesterInvalidBodyLength(self.client, self.servers)
