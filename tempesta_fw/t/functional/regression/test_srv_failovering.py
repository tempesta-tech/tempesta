"""
Test Servers connections failovering.
"""

from __future__ import print_function
import unittest
import random
import socket
from helpers import deproxy, tf_cfg, tempesta, remote
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class FailoveringTest(functional.FunctionalTest):
    """Spawn a lot of servers, close half on connections

    TODO: Check that TempestaFW keeps configured failovering intervals.
    """

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def create_tester(self, message_chain):
        self.tester = FailoverTester(message_chain, self.client, self.servers)

    def init(self):
        self.tempesta.config.set_defconfig('')

        self.create_servers()
        self.configure_tempesta()

        self.tempesta.start()
        self.create_client()
        chains = [deproxy.MessageChain.empty()]
        self.create_tester(chains)

    def test_on_close(self):
        self.init()
        self.tester.run()
        self.tester.random_close()
        self.assertFalse(self.tester.is_srvs_ready())
        self.tester.run()

    def test_on_shutdown(self):
        self.init()
        self.tester.run()
        self.tester.random_shutdown()
        self.assertFalse(self.tester.is_srvs_ready())
        self.tester.run()


class FailoverTester(deproxy.Deproxy):

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        self.expected_conns_n = sum([s.conns_n for s in self.servers])

    def check_expectations(self):
        assert self.is_srvs_ready()

    def random_close(self):
        for i in range (self.expected_conns_n // 4):
            conn = random.choice(self.srv_connections)
            if conn:
                conn.handle_close()

    def random_shutdown(self):
        for i in range (self.expected_conns_n // 4):
            conn = random.choice(self.srv_connections)
            if conn:
                conn.socket.shutdown(socket.SHUT_RDWR)
                conn.handle_close()
