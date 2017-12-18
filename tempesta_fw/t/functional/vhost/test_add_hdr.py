"""Functional tests for adding user difined headers."""

from __future__ import print_function
from testers import functional
from helpers import chains

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestAddHeader(functional.FunctionalTest):

    location = '/'

    def config_append_directive(self, hdrs, location=None):
        if location is not None:
            self.config = self.config + ('location prefix "%s" {\n' % location)
        for (name, val) in hdrs:
            self.config = self.config + ('hdr_add %s "%s";\n' % (name, val))
        if location is not None:
            self.config = self.config + '}\n'

    def make_chain(self, hdrs):
        self.msg_chain = chains.proxy()
        for (name, val) in hdrs:
            self.msg_chain.response.headers[name] = val
        self.msg_chain.response.update()

    def add_hdrs(self, hdrs, location=None):
        self.config = ''
        self.config_append_directive(hdrs, location)
        self.make_chain(hdrs)

    def test_add_one_hdr(self):
        hdrs = [('X-My-Hdr', 'some text')]
        self.add_hdrs(hdrs)
        self.generic_test_routine(self.config, [self.msg_chain])

    def test_add_some_hdrs(self):
        hdrs = [('X-My-Hdr', 'some text'),
                ('X-My-Hdr-2', 'some other text')]
        self.add_hdrs(hdrs)
        self.generic_test_routine(self.config, [self.msg_chain])

    def test_add_some_hdrs_custom_location(self):
        hdrs = [('X-My-Hdr', 'some text'),
                ('X-My-Hdr-2', 'some other text')]
        self.add_hdrs(hdrs, self.location)
        self.generic_test_routine(self.config, [self.msg_chain])

    def test_add_hdrs_derive_config(self):
        '''Derive general settings to custom location.'''
        hdrs = [('X-My-Hdr', 'some text')]
        self.config = ''
        self.config_append_directive(hdrs)
        self.config_append_directive([], self.location)
        self.make_chain(hdrs)
        self.generic_test_routine(self.config, [self.msg_chain])

    def test_add_hdrs_override_config(self):
        '''Override general settings to custom location.'''
        hdrs = [('X-My-Hdr', 'some text')]
        o_hdrs = [('X-My-Hdr-2', 'some other text')]
        self.config = ''
        self.config_append_directive(hdrs)
        self.config_append_directive(o_hdrs, self.location)
        self.make_chain(o_hdrs)
        self.generic_test_routine(self.config, [self.msg_chain])

# TODO: add tests for different vhosts, when vhosts will be implemented.
