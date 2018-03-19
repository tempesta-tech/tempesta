""" Testing for missing or wrong body length in request """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import unittest
import body_generator
import os

from . import tester

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

def generate_chain(method='GET', expect_400=False, connection=None):
    base = chains.base(method=method)
    chain = tester.BadLengthMessageChain(request=base.request,
                                         expected_responses=[base.response],
                                         forwarded_request=base.fwd_request,
                                         server_response=base.server_response)
    if expect_400:
        chain.responses.append(chains.response_400(connection=connection))
    return chain

class TesterCorrectBodyLength(tester.BadLengthDeproxy):
    """ Tester """
    def create_base(self):
        base = generate_chain(method='PUT')
        return (base, len(base.request.body))

    def __init__(self, *args, **kwargs):
        tester.BadLengthDeproxy.__init__(self, *args, **kwargs)
        base = self.create_base()
        self.message_chains = [req_body_length(base[0], base[1])]
        self.cookies = []

class TesterMissingBodyLength(TesterCorrectBodyLength):
    """ Tester """
    def create_base(self):
        base = generate_chain(method='PUT', expect_400=True)
        return (base, None)

class TesterSmallBodyLength(TesterCorrectBodyLength):
    """ Tester """
    def create_base(self):
        base = generate_chain(method='PUT', expect_400=True)
        return (base, len(base.request.body) - 15)

class TesterDuplicateBodyLength(deproxy.Deproxy):
    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = chains.base(method='PUT')
        cl = base.request.headers['Content-Length']

        base.request.headers.add('Content-Length', cl)
        base.request.build_message()

        base.fwd_request = deproxy.Request()

        base.response = chains.response_400(connection='keep-alive')

        self.message_chains = [base]
        self.cookies = []

class TesterInvalidBodyLength(deproxy.Deproxy):
    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = chains.base(method='PUT')
        base.request.headers['Content-Length'] = 'invalid'
        base.request.build_message()
        base.response = chains.response_400(connection='keep-alive')
        base.fwd_request = deproxy.Request()
        self.message_chains = [base]
        self.cookies = []

class TesterSecondBodyLength(TesterDuplicateBodyLength):
    def second_length(self, content_length):
        len = int(content_length)
        return "%i" % (len - 1)

    def expected_response(self):
        return chains.response_400(connection='keep-alive')

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        base = chains.base(method='PUT')
        cl = base.request.headers['Content-Length']

        duplicate = self.second_length(cl)
        base.request.headers.add('Content-Length', duplicate)
        base.request.build_message()

        base.response = self.expected_response()

        base.fwd_request = deproxy.Request()

        self.message_chains = [base]
        self.cookies = []


class RequestCorrectBodyLength(functional.FunctionalTest):
    """ Wrong body length """
    config = 'cache 0;\nblock_action error reply;\nblock_action attack reply;\n'

    def create_client(self):
        self.client = tester.ClientMultipleResponses()

    def create_tester(self):
        self.tester = TesterCorrectBodyLength(self.client, self.servers)

    def test(self):
        """ Test """
        self.generic_test_routine(self.config, [])

class RequestMissingBodyLength(RequestCorrectBodyLength):
    """ Wrong body length """

    def create_tester(self):
        self.tester = TesterMissingBodyLength(self.client, self.servers)

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
    def create_tester(self):
        self.tester = TesterSmallBodyLength(self.client, self.servers)

class RequestDuplicateBodyLength(functional.FunctionalTest):
    config = 'cache 0;\nblock_action error reply;\nblock_action attack reply;\n'

    def create_client(self):
        self.client = deproxy.Client()

    def create_tester(self):
        self.tester = TesterDuplicateBodyLength(self.client, self.servers)

    def test(self):
        """ Test """
        self.generic_test_routine(self.config, [])

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

class RequestSecondBodyLength(RequestDuplicateBodyLength):
    def create_tester(self):
        self.tester = TesterSecondBodyLength(self.client, self.servers)

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

class RequestInvalidBodyLength(RequestSecondBodyLength):
    def create_tester(self):
        self.tester = TesterInvalidBodyLength(self.client, self.servers)
