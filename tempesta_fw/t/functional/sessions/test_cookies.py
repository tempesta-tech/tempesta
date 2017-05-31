from __future__ import print_function
import sys
import unittest
import re
from helpers import deproxy
from testers import functional
from . import cookies

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TestNoCookiesSupport(functional.FunctionalTest):
    """ Functional test for using cookies cookie. """

    config = (
        'cache 0;\n'
        'sticky;\n'
        'sticky_secret "f00)9eR59*_/22";\n'
        '\n')

    def create_tester(self, message_chain):
        self.tester = cookies.TesterIgnoreCookies(message_chain, self.client,
                                                  self.servers)

    def test(self):
       self.generic_test_routine(self.config, [])


class TestCookiesSupport(TestNoCookiesSupport):

    def create_tester(self, message_chain):
        self.tester = cookies.TesterUseCookies(message_chain, self.client,
                                               self.servers)


class TestNoEnforcedCookiesSupport(TestNoCookiesSupport):

    config = (
        'cache 0;\n'
        'sticky enforce;\n'
        'sticky_secret "f00)9eR59*_/22";\n'
        '\n')

    def create_tester(self, message_chain):
        self.tester = cookies.TesterIgnoreEnforcedCookies(
            message_chain, self.client, self.servers)


class TestEnforcedCookiesSupport(TestNoEnforcedCookiesSupport):

    def create_tester(self, message_chain):
        self.tester = cookies.TesterUseEnforcedCookies(
            message_chain, self.client, self.servers)
