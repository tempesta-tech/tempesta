"""
Hash scheduler pins resources to specific servers and connections. Stress
test. Can't track server connections here, but real HTTP servers and clients
are used.
"""

import sys
from helpers import tempesta
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class BindToServer(stress.StressTest):
    """ Hash scheduler binds URIs to specific connections, so only one server
    must pull all the load if we try to get the same resource over and over
    again.
    """

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())
        # Hash scheduler can't use the same server for the same requests if
        # it can go offline.
        for s in self.servers:
            s.config.set_ka(sys.maxsize)

    def configure_tempesta(self):
        """Configure Tempesta to use hash scheduler instead of default one.
        """
        stress.StressTest.configure_tempesta(self)
        for sg in self.tempesta.config.server_groups:
            sg.sched = 'hash'

    def assert_servers(self):
        self.servers_get_stats()
        # Only one server must pull all the load.
        loaded = 0
        for s in self.servers:
            if s.requests:
                loaded += 1
                self.assertEqual(self.tempesta.stats.cl_msg_forwarded,
                                 s.requests)
        self.assertEqual(loaded, 1)

    def test_hash(self):
        self.generic_test_routine('cache 0;\n')

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
