"""
With sticky sessions each client is pinned to only one server in group.
"""

from __future__ import print_function
from helpers import control, tempesta, tf_cfg
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class OneClient(stress.StressTest):

    config = (
        'cache 0;\n'
        'sticky enforce;\n'
        'sticky_secret "f00)9eR59*_/22";\n'
        '\n')

    def configure_tempesta(self):
        stress.StressTest.configure_tempesta(self)
        for sg in self.tempesta.config.server_groups:
            sg.options = 'sticky_sessions;'

    def create_clients(self):
        self.wrk = control.Wrk()
        self.wrk.set_script("cookie-one-client")
        self.clients = [self.wrk]

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def assert_servers(self):
        self.servers_get_stats()
        # Wrk does not treat 302 responses as errors, but 302 response means
        # that message was not forwarded to server.
        expected_err = int(tf_cfg.cfg.get('General', 'concurrent_connections'))
        exp_min = self.wrk.requests -  expected_err - 1
        exp_max = self.wrk.requests
        # Only one server must pull all the load.
        loaded = 0
        for s in self.servers:
            if s.requests:
                loaded += 1
                self.assertTrue(
                    s.requests in range(exp_min, exp_max + 1),
                    msg=("Number of requests forwarded to server (%d) "
                         "doesn't match expected value: [%d, %d]"
                         % (s.requests, exp_min, exp_max + 1))
                    )
        self.assertEqual(loaded, 1)

    def test(self):
        self.generic_test_routine(self.config)


class LotOfClients(OneClient):

    # Override maximum number of clients
    clients_num = min(int(tf_cfg.cfg.get('General', 'concurrent_connections')),
                      1000)

    def create_clients(self):
        # Create one thread per client to set unique User-Agent header for
        # each client.
        self.wrk = control.Wrk(threads=self.clients_num)
        self.wrk.connections = self.wrk.threads
        self.wrk.set_script("cookie-many-clients")
        self.clients = [self.wrk]

    def assert_servers(self):
        stress.StressTest.assert_servers(self)
