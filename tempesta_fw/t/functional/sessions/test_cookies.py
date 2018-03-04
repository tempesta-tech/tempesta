from __future__ import print_function
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

    def create_tester(self):
        self.tester = cookies.TesterIgnoreCookies(self.client, self.servers)

    def test(self):
        self.generic_test_routine(self.config, [])


class TestCookiesSupport(TestNoCookiesSupport):

    def create_tester(self):
        self.tester = cookies.TesterUseCookies(self.client, self.servers)


class TestNoEnforcedCookiesSupport(TestNoCookiesSupport):

    config = (
        'cache 0;\n'
        'sticky enforce;\n'
        'sticky_secret "f00)9eR59*_/22";\n'
        '\n')

    def create_tester(self):
        self.tester = \
            cookies.TesterIgnoreEnforcedCookies(self.client, self.servers)


class TestEnforcedCookiesSupport(TestNoEnforcedCookiesSupport):

    def create_tester(self):
        self.tester = \
            cookies.TesterUseEnforcedCookies(self.client, self.servers)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
