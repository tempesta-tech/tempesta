"""Functional tests of caching different methods."""

from __future__ import print_function
import unittest
from helpers import deproxy, tf_cfg, tempesta
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TestCacheMethods(functional.FunctionalTest):

    messages = 10

    # Replicated cache mode, no need to test other modes in this test.
    cache_mode = 2

    allow_method_caching = True

    # Methods, that can be cached by TempestaFW.
    cacheable_methods = ['COPY', 'DELETE', 'GET', 'HEAD', 'LOCK', 'MKCOL',
                         'MOVE', 'OPTIONS', 'PATCH', 'POST', 'PROPFIND',
                         'PROPPATCH', 'PUT', 'TRACE', 'UNLOCK']

    def chain(self, method, uri='/page.html', cache_alowed=True):
        if self.cache_mode == 0:
            cache_alowed = False
        if cache_alowed:
            return cache_chains(self.messages, method=method, uri=uri)
        return proxy_chains(self.messages, method=method, uri=uri)

    def try_method(self, method):
        tf_cfg.dbg(3, '\tTest method %s.' % method)
        chain = self.chain(method=method,
                           cache_alowed=(method in self.cacheable_methods))
        if self.allow_method_caching:
            cache_method = method
        else:
            cache_method = 'GET' if method != 'GET' else 'HEAD'
        config = ('cache %d;\n'
                  'cache_fulfill * *;\n'
                  'cache_methods %s;\n'
                  % (self.cache_mode, cache_method))
        self.generic_test_routine(config, chain)

    def test_COPY(self):
        self.try_method('COPY')

    def test_DELETE(self):
        self.try_method('DELETE')

    def test_GET(self):
        self.try_method('GET')

    def test_HEAD(self):
        self.try_method('HEAD')

    def test_LOCK(self):
        self.try_method('LOCK')

    def test_MKCOL(self):
        self.try_method('MKCOL')

    def test_MOVE(self):
        self.try_method('MOVE')

    def test_OPTIONS(self):
        self.try_method('OPTIONS')

    def test_PATCH(self):
        self.try_method('PATCH')

    def test_POST(self):
        self.try_method('POST')

    def test_PROPFIND(self):
        self.try_method('PROPFIND')

    def test_PROPPATCH(self):
        self.try_method('PROPPATCH')

    def test_PUT(self):
        self.try_method('PUT')

    def test_TRACE(self):
        self.try_method('TRACE')

    def test_UNLOCK(self):
        self.try_method('UNLOCK')


class TestCacheMethodsNC(TestCacheMethods):

    cacheable_methods = []
    allow_method_caching = False


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

def cache_chains(count, method, uri):
    chains = [proxy_chain(method, uri)]
    chain = cache_chain(method, uri)
    cached_chains = [chain for i in range (1, count)]
    return chains + cached_chains

def proxy_chains(count, method, uri):
    chain = proxy_chain(method, uri)
    return [chain for i in range (count)]
