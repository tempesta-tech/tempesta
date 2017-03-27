"""
With sticky sessions each client is pinned to only one server in group.
"""

from __future__ import print_function
import unittest, sys
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
        siege = control.Siege()
        siege.rc.set_option('limit', '4096')
        siege.rc.set_option('connection', 'keep-alive')
        siege.rc.set_option('parser', 'false')
        self.clients = [siege]

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def assert_servers(self):
        self.servers_get_stats()
        expected_err = int(tf_cfg.cfg.get('General', 'concurrent_connections'))
        exp_min = self.clients[0].requests -  expected_err - 1
        exp_max = self.clients[0].requests +  expected_err + 1
        # Only one server must pull all the load.
        loaded = 0
        for s in self.servers:
            if s.requests:
                loaded += 1
                self.assertTrue(s.requests in range(exp_min, exp_max))
        self.assertEqual(loaded, 1)

    def test(self):
        self.generic_test_routine(self.config)


class LotOfClients(OneClient):

    def create_clients(self):
        # Don't use client array here. Too slow for running
        self.siege = control.Siege()
        self.siege.rc.set_option('connection', 'keep-alive')
        self.siege.rc.set_option('parser', 'false')
        self.siege.connections = 25
        self.clients = [self.siege]

    def test(self):
        self.tempesta.config.set_defconfig(self.config)
        self.configure_tempesta()
        control.servers_start(self.servers)
        self.tempesta.start()

        control.clients_parallel_load(self.siege)

        self.tempesta.get_stats()
        self.assert_clients()
        self.assert_tempesta()
