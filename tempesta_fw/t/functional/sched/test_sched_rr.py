import unittest, sys, math, random
from helpers import tfw_test, tf_cfg, control, tempesta

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class RRTester(tfw_test.Loader):

    def run_test(self, ka_reqs):
        for s in self.servers:
            s.config.set_ka(ka_reqs)
        self.generic_test_routine('cache 0;\n')


class Issue383(RRTester):
    """ #383 Regression test.

    Some requests will be dropped if all the connections across all
    servers are in the failovering state.
    More info at: https://github.com/tempesta-tech/tempesta/issues/383
    """

    @unittest.expectedFailure
    def test_limited_ka(self):
        """ #383: Few upstream connections cause requests drops. """
        self.run_test(100)

    def test_unlimited_ka(self):
        """ #383: Unlimited upstream keepalive preset saves from drops. """
        self.run_test(sys.maxsize)


class FairLoadEqualConns(RRTester):
    """ Round-Robin scheduler loads all the upstream servers in the fair
        way. In this test servers have the same connections count.
        """

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def assert_servers(self):
        for s in self.servers:
            self.assertTrue(s.get_stats())

        cl_reqs = self.tempesta.stats.cl_msg_forwarded
        s_reqs_expected = cl_reqs / len(self.servers)
        s_reqs = 0
        for s in self.servers:
            self.assertTrue(math.fabs(s.requests - s_reqs_expected) <
                            (0.005 * s_reqs_expected))
            s_reqs += s.requests
        self.assertEqual(s_reqs, self.tempesta.stats.cl_msg_forwarded)

    @unittest.skip('Unreliable due to #383')
    def test_limited_ka(self):
        self.run_test(100)

    def test_unlimited_ka(self):
        self.run_test(sys.maxsize)



class FairLoadRandConns(FairLoadEqualConns):
    """ Same as FairLoadEqualConns, but in this test servers have random
    connections count.
    """

    def create_servers(self):
        """ Save number of connections to each upstream server """
        FairLoadEqualConns.create_servers(self)
        for s in self.servers:
            s.conns_n = random.randrange(1, tempesta.server_conns_max())
