"""
Round-robin scheduler is fast and fair scheduler. First it choses server in
round-robin manner, then does the same to choose connection to server. Load of
all servers is quite identical even for servers with different connections
count.
"""

import unittest
import math
import random
import sys
from helpers import tempesta
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class RrStressTest(stress.StressTest):
    """Stress test for RR scheduler: max servers in group, default keep-alive
    settings. Clients must not recieve non-2xx answers.
    """

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def test_rr(self):
        self.generic_test_routine('cache 0;\n')


class FairLoadEqualConns(RrStressTest):
    """ Round-Robin scheduler loads all the upstream servers in the fair
    way. In this test servers have the same connections count.
    """

    # Precision of fair loading.
    precision = 0.005

    def assert_servers(self):
        """All servers must recieve almost equal amount of requests."""
        self.servers_get_stats()
        cl_reqs = self.tempesta.stats.cl_msg_forwarded
        s_reqs_expected = cl_reqs / len(self.servers)
        s_reqs = 0
        for s in self.servers:
            self.assertTrue(math.fabs(s.requests - s_reqs_expected) <
                            (self.precision * s_reqs_expected))
            s_reqs += s.requests
        self.assertEqual(s_reqs, self.tempesta.stats.cl_msg_forwarded)

    def test_rr(self):
        # Server connections failovering may affect load distribution.
        for s in self.servers:
            s.config.set_ka(sys.maxsize)
        self.generic_test_routine('cache 0;\n')


class FairLoadRandConns(FairLoadEqualConns):
    """ Same as FairLoadEqualConns, but in this test servers have random
    connections count. Roun-robin scheduler still distributes load uniformely
    arcross all the servers.
    """

    def create_servers(self):
        """ Save number of connections to each upstream server """
        FairLoadEqualConns.create_servers(self)
        for s in self.servers:
            s.conns_n = random.randrange(1, tempesta.server_conns_max())
