""" Testing for missing or wrong body length in request/response """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import unittest
import body_generator
import os

from . import client

from testers import functional
from helpers import tf_cfg, control, tempesta, remote, deproxy, chains

def req_body_length(base, length):
    """ Generate chain with missing or specified body length """
    for msg in ['request', 'fwd_request']:
        field = getattr(base, msg)
        field.headers.delete_all('Content-Length')
        if length != None:
            field.headers.add('Content-Length', '%i' % length)

    base.fwd_request.update()
    base.request.build_message()
    return base

def generate_chain(method='GET', expect_403=False):
    base = chains.base(method=method)
    chain = client.BadLengthMessageChain(request=base.request,
                                         expected_responses=[base.response],
                                         forwarded_request=base.fwd_request,
                                         server_response=base.server_response)
    if expect_403:
        chain.responses.append(chains.response_403())
    return chain

class TesterCorrectBodyLength(client.BadLengthDeproxy):
    """ Tester """
    def create_base(self):
        base = generate_chain(method='PUT')
        return (base, len(base.request.body))

    def __init__(self, *args, **kwargs):
        client.BadLengthDeproxy.__init__(self, *args, **kwargs)
        base = self.create_base()
        self.message_chains = [req_body_length(base[0], base[1])]
        self.cookies = []

class TesterMissingBodyLength(TesterCorrectBodyLength):
    """ Tester """
    def create_base(self):
        base = generate_chain(method='PUT', expect_403=True)
        return (base, None)

class TesterSmallBodyLength(TesterCorrectBodyLength):
    """ Tester """
    def create_base(self):
        base = generate_chain(method='PUT', expect_403=True)
        return (base, len(base.request.body) - 15)

class TesterLargeBodyLength(TesterCorrectBodyLength):
    """ Tester """
    def create_base(self):
        base = generate_chain(method='PUT', expect_403=True)
        return (base, len(base.request.body) + 15)

class RequestCorrectBodyLength(functional.FunctionalTest):
    """ Wrong body length """
    config = 'cache 0;\nblock_action error reply;\nblock_action attack reply;\n'

    def create_client(self):
        self.client = client.ClientMultipleResponses()

    def create_tester(self, message_chain):
        self.tester = TesterCorrectBodyLength(message_chain, self.client, self.servers)

    def test(self):
        """ Test """
        self.generic_test_routine(self.config, [])

class RequestMissingBodyLength(RequestCorrectBodyLength):
    """ Wrong body length """

    def create_tester(self, message_chain):
        self.tester = TesterMissingBodyLength(message_chain, self.client, self.servers)

    def assert_tempesta(self):
        msg = 'Tempesta have errors in processing HTTP %s.'
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 1,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 0,
                         msg=(msg % 'responses'))
        self.assertEqual(self.tempesta.stats.cl_msg_other_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_other_errors, 0,
                         msg=(msg % 'responses'))

class RequestSmallBodyLength(RequestMissingBodyLength):
    """ Wrong body length """
    def create_tester(self, message_chain):
        self.tester = TesterSmallBodyLength(message_chain, self.client, self.servers)

class RequestLargeBodyLength(RequestMissingBodyLength):
    """ Wrong body length """
    def create_tester(self, message_chain):
        self.tester = TesterLargeBodyLength(message_chain, self.client, self.servers)
