"""
With sticky sessions each client is pinned to only one server in group.
"""

from __future__ import print_function
import sys
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
        self.wrk = control.Wrk(threads = 1)
        self.wrk.set_script("cookie-one-client")
        self.clients = [self.wrk]

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def assert_servers(self):
        self.servers_get_stats()
        # Negative allowance: this means some requests are not forwarded to the
        # server. This happens because some (at least one per wrk thread,
        # at most one per connection) requests are sent without a session cookie
        # and replied 302 by Tempesta without any forwarding, which is still
        # considered a "success" by wrk. So, [1; concurrent_connections]
        # requests will not be received by the backend.
        # This allowance is specific to the session stress tests.
        exp_min = self.wrk.requests - self.wrk.connections
        # Positive allowance: this means some responses are missed by the client.
        # It is believed (nobody actually checked though...) that wrk does not
        # wait for responses to last requests in each connection before closing
        # it and does not account for those requests.
        # So, [0; concurrent_connections] responses will be missed by the client.
        exp_max = self.wrk.requests + self.wrk.connections - 1
        # Only one server must pull all the load.
        loaded = 0
        for s in self.servers:
            if s.requests:
                loaded += 1
                self.assertTrue(
                    s.requests >= exp_min and s.requests <= exp_max,
                    msg=("Number of requests forwarded to server (%d) "
                         "doesn't match expected value: [%d, %d]"
                         % (s.requests, exp_min, exp_max))
                    )
        self.assertEqual(loaded, 1)

    def test(self):
        # Server connections failovering is tested in functional test.
        # It will cause only non-200 responses.
        for s in self.servers:
            s.config.set_ka(sys.maxsize)
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

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
