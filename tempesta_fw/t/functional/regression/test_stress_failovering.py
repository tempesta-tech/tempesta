"""
Stress failovering testing: generate HTTP traffic with wrk, all requests must
be served correctly. No matter how much keep-alive request are configured on
the server.

Refer to issue #383 for more information.
"""

from __future__ import print_function
import unittest
import sys
from helpers import tempesta
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class RoudRobinFailovering(stress.StressTest):
    """Use Round-robin scheduler (default) with different keep-alive requests
    configuration on HTTP server.

    Use one server with default connections count. Since overall amount of
    connections are small, failovering procedure will be loaded a lot.
    We do not need a lot of connections for this test: it will just make
    connections to live a little bit more under load.
    """

    def run_test(self, ka_reqs):
        """Configure server's keep-alive requests count for one session and
        start generic test.
        """
        for s in self.servers:
            s.config.set_ka(ka_reqs)
        self.generic_test_routine('cache 0;\n')

    @unittest.expectedFailure
    def test_limited_ka(self):
        """Small amount of keep-alive requests, make Tempesta failover
        connections on a high rates.
        """
        self.run_test(100)

    def test_unlimited_ka(self):
        """Almost unlimited maximum amount of requests during one connection.
        No connections failovering in this case.
        """
        self.run_test(sys.maxsize)


class HashFailovering(RoudRobinFailovering):
    """Absolutely the same as RoudRobinFailovering, bus uses `hash` scheduler
    instead.
    """

    def configure_tempesta(self):
        """Configure Tempesta to use hash scheduler instead of default one.
        """
        stress.StressTest.configure_tempesta(self)
        for sg in self.tempesta.config.server_groups:
            sg.sched = 'hash'
