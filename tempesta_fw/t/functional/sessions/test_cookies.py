from __future__ import print_function
import unittest, sys
from helpers import tfw_test, tf_cfg, control

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

config_cookies = """
cache 0;
sticky;
sticky_secret "f00)9eR59*_/22";
sess_lifetime 100;
"""
config_cookies_enforced = """
cache 0;
sticky enforce;
sticky_secret "f00)9eR59*_/22";
sess_lifetime 100;
"""

# UserAgent headers example, id must be filled before using
ua_example = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0; id:%d) Gecko/20100101 Firefox/47.0'

class StressCookies(tfw_test.Loader):
    """ Stress test for cookies. Clients do not support cookies. """

    def create_clients_helper(self, client_class):
        """ Cookies depends on IP adress and UserAgent header. We cannot affect
        ip in the test, but we can start several traffic generators with unique
        UserAgent headers each instead.
        """
        self.clients = []
        conns = int(tf_cfg.cfg.get('General', 'concurrent_connections'))
        for i in range(conns):
            client = client_class()
            client.set_user_agent(ua_example % i)
            client.connections = 1
            self.clients.append(client)

    def create_clients(self):
        self.create_clients_helper(control.Wrk)

    def test_cookies(self):
        # FIXME: #383 workaround
        for s in self.servers:
            s.config.set_ka(sys.maxsize)
        self.generic_test_routine(config_cookies)


class StressEnforcedCookies(StressCookies):
    """ Stress test for cookies. Clients support cookies. Cookies are enforced.
    """

    def create_clients(self):
        self.create_clients_helper(control.Siege)
