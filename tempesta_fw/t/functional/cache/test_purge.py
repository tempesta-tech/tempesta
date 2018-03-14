"""Functional tests of caching different methods."""

from __future__ import print_function
import unittest
from helpers import tf_cfg, chains
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
        result = [
            # All cacheable method to the resource must be cached
            chains.proxy(method='GET', uri=uri),
            chains.proxy(method='HEAD', uri=uri),
            chains.cache(method='GET', uri=uri),
            chains.cache(method='HEAD', uri=uri),

            chains.cache(method='PURGE', uri=uri),
            # All cached responses was removed, expect re-caching them
            chains.proxy(method='GET', uri=uri),
            chains.proxy(method='HEAD', uri=uri),
            chains.cache(method='GET', uri=uri),
            chains.cache(method='HEAD', uri=uri)
            ]
        return result

    @unittest.expectedFailure
    def test_purge(self):
        """"Issue #788 must be resolved to make the test pass"""
        self.generic_test_routine(self.config, self.chains())
