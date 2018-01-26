from __future__ import print_function
from testers import functional
from helpers import deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class CacheAgeTester(deproxy.Deproxy):
    """Tester helper for Age: header verification."""

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)

    def recieved_response(self, response):
        sent = self.current_chain.server_response
        expected = self.current_chain.response
        request = self.current_chain.request
        if (not sent.msg
            and expected.status != '304'
            and expected.status != '412'
            and request.method != 'PURGE'):
            assert 'Age' in response.headers, \
                'Age header is absent in response from cache!'
            expected.headers.delete_all('Age')
            expected.headers.add('Age', response.headers['Age'])
            expected.update()

        deproxy.Deproxy.recieved_response(self, response)


class TestCacheAge(functional.FunctionalTest):

    def create_tester(self, message_chain):
        self.tester = CacheAgeTester(message_chain, self.client, self.servers)
