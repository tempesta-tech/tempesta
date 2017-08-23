"""Regression tests for invalid requests and responses."""

from __future__ import print_function
import unittest
from testers import functional
from helpers import chains, deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestInvalidResponse(functional.FunctionalTest):

    config = (
        'cache 0;\n'
    )

    @unittest.expectedFailure
    def test_no_crlf_before_body(self):
        chain = chains.proxy()
        chain.server_response.msg = chain.server_response.msg.replace('\r\n\r\n', '\r\n', 1)
        chain.response = deproxy.Response()
        self.generic_test_routine(self.config, [chain])
