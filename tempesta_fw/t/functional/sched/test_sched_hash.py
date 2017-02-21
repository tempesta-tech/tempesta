import unittest, sys
from helpers import tfw_test, tempesta

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HashTester(tfw_test.Loader):

    def configure_tempesta(self):
        tfw_test.Loader.configure_tempesta(self)
        # Use hash scheduler instead of Round-Robin
        for sg in self.tempesta.config.server_groups:
            sg.sched = 'hash'

    def run_test(self, ka_reqs):
        for s in self.servers:
            s.config.set_ka(ka_reqs)
        self.generic_test_routine('cache 0;\n')



class Issue383(HashTester):
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



class BindToServer(HashTester):
    """ Hash scheduler binds URIs to specific connections, so only one server
    must pull all the load if we try to get the same resource over and over.
    """

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def assert_servers(self):
        self.servers_get_stats()
        reqs = self.tempesta.stats.cl_msg_forwarded
        # Only one server must pull all the load.
        loaded = 0
        for s in self.servers:
            if s.requests:
                loaded += 1
                self.assertEqual(self.tempesta.stats.cl_msg_forwarded,
                                 s.requests)
        self.assertEqual(loaded, 1)

    @unittest.expectedFailure
    def test_limited_ka(self):
        """ #383: Few upstream connections cause requests drops. """
        self.run_test(100)

    def test_unlimited_ka(self):
        """ #383: Unlimited upstream keepalive preset saves from drops. """
        self.run_test(sys.maxsize)
