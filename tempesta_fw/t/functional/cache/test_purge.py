"""Functional tests of caching different methods."""

from __future__ import print_function
from helpers import tf_cfg, deproxy
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# TODO: add tests for 'cache_purge_acl'

class TestPurge(functional.FunctionalTest):

    config = ('cache 2;\n'
              'cache_fulfill * *;\n'
              'cache_methods GET HEAD;\n'
              'cache_purge;\n'
              'cache_purge_acl %s;\n'
              % tf_cfg.cfg.get('Client', 'ip'))

    def chains(self):
        uri = '/page.html'
        chains = [# All cacheable method to the resource must be cached
                  proxy_chain(method='GET', uri=uri),
                  proxy_chain(method='HEAD', uri=uri),
                  cache_chain(method='GET', uri=uri),
                  cache_chain(method='HEAD', uri=uri),

                  purge_chain(uri=uri),
                  # All cached responses was removed, expect re-caching them
                  proxy_chain(method='GET', uri=uri),
                  proxy_chain(method='HEAD', uri=uri),
                  cache_chain(method='GET', uri=uri),
                  cache_chain(method='HEAD', uri=uri)
                  ]
        return chains

    def test_purge(self):
        self.generic_test_routine(self.config, self.chains())


def remove_body(response):
    response.body = ''
    response.body_void = True
    response.update()

def cache_chain(method, uri):
    chain = functional.base_message_chain(uri=uri, method=method)
    chain.no_forward()
    if method == 'HEAD':
        remove_body(chain.response)
    return chain

def proxy_chain(method, uri):
    chain = functional.base_message_chain(uri=uri, method=method)
    if method == 'HEAD':
        remove_body(chain.response)
        remove_body(chain.server_response)
    return chain

def purge_chain(uri):
    chain = functional.base_message_chain(uri=uri, method='PURGE')
    chain.no_forward()
    headers = [
        'Connection: keep-alive',
        'Content-Length: 0']
    chain.response = deproxy.Response.create(200, headers, date=True, body='')
    return chain
