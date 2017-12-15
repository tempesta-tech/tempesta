"""Functional tests for adding user difined headers."""

from __future__ import print_function
from testers import functional
from helpers import chains

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestAddHeader(functional.FunctionalTest):

    def add_hdrs(self, hdrs, location=None):
        self.config = ''
        self.msg_chain = chains.proxy()

        if location is not None:
            self.config = self.config + ('location prefix "%s" {\n' % location)

        for (name, val) in hdrs:
            self.config = self.config + ('hdr_add %s "%s";\n' % (name, val))
            self.msg_chain.response.headers[name] = val
        self.msg_chain.response.update()

        if location is not None:
            self.config = self.config + '}\n'

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
        self.add_hdrs(hdrs, '/')
        self.generic_test_routine(self.config, [self.msg_chain])
