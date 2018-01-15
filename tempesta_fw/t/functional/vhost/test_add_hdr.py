"""Functional tests for adding user difined headers."""

from __future__ import print_function
from testers import functional
from helpers import chains

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestReqAddHeader(functional.FunctionalTest):

    location = '/'
    directive = 'req_hdr_add'

    def config_append_directive(self, hdrs, location=None):
        if location is not None:
            self.config = self.config + ('location prefix "%s" {\n' % location)
        for (name, val) in hdrs:
            self.config = self.config + ('%s %s "%s";\n' % (self.directive, name, val))
        if location is not None:
            self.config = self.config + '}\n'

    def make_chain(self, hdrs):
        self.msg_chain = chains.proxy()
        for (name, val) in hdrs:
            self.msg_chain.fwd_request.headers[name] = val
        self.msg_chain.fwd_request.update()

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


class TestRespAddHeader(TestReqAddHeader):

    directive = 'resp_hdr_add'

    def make_chain(self, hdrs):
        self.msg_chain = chains.proxy()
        for (name, val) in hdrs:
            self.msg_chain.response.headers[name] = val
        self.msg_chain.response.update()


class TestReqSetHeader(TestReqAddHeader):

    directive = 'req_hdr_set'

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        self.msg_chain = chains.proxy()
        for (name, val) in orig_hdrs:
            self.msg_chain.request.headers[name] = val
            self.msg_chain.fwd_request.headers[name] = val
        for (name, val) in hdrs:
            self.msg_chain.fwd_request.headers[name] = val
        self.msg_chain.request.update()
        self.msg_chain.fwd_request.update()


class TestRespSetHeader(TestReqSetHeader):

    directive = 'resp_hdr_set'

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        self.msg_chain = chains.proxy()
        for (name, val) in orig_hdrs:
            self.msg_chain.server_response.headers[name] = val
            self.msg_chain.response.headers[name] = val
        for (name, val) in hdrs:
                self.msg_chain.response.headers[name] = val
        self.msg_chain.server_response.update()
        self.msg_chain.response.update()


class TestReqDelHeader(TestReqAddHeader):

    directive = 'req_hdr_set'

    def config_append_directive(self, hdrs, location=None):
        if location is not None:
            self.config = self.config + ('location prefix "%s" {\n' % location)
        for (name, val) in hdrs:
            self.config = self.config + ('%s %s;\n' % (self.directive, name))
        if location is not None:
            self.config = self.config + '}\n'

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        self.msg_chain = chains.proxy()
        for (name, val) in orig_hdrs:
            self.msg_chain.request.headers[name] = val
            self.msg_chain.fwd_request.headers[name] = val
        for (name, val) in hdrs:
            del self.msg_chain.fwd_request.headers[name]
        self.msg_chain.request.update()
        self.msg_chain.fwd_request.update()


class TestRespDelHeader(TestReqDelHeader):

    directive = 'resp_hdr_set'

    def make_chain(self, hdrs):
        orig_hdrs = [('X-My-Hdr', 'original text'),
                     ('X-My-Hdr-2', 'other original text')]
        self.msg_chain = chains.proxy()
        for (name, val) in orig_hdrs:
            self.msg_chain.server_response.headers[name] = val
            self.msg_chain.response.headers[name] = val
        for (name, val) in hdrs:
            del self.msg_chain.response.headers[name]
        self.msg_chain.server_response.update()
        self.msg_chain.response.update()


# TODO: add tests for different vhosts, when vhosts will be implemented.
