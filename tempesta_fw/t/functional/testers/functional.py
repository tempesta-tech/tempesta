from __future__ import print_function
import unittest
from helpers import tf_cfg, control, tempesta, deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class FunctionalTest(unittest.TestCase):

    def create_client(self):
        """ Override to set desired list of benchmarkers and their options. """
        self.client = deproxy.Client()

    def create_tempesta(self):
        """ Normally no override is needed.
        Create controller for TempestaFW and add all servers to default group.
        """
        self.tempesta = control.Tempesta()

    def configure_tempesta(self):
        """ Add all servers to default server group with default scheduler. """
        sg = tempesta.ServerGroup('default')
        # We run server on the Client host.
        ip = tf_cfg.cfg.get('Client', 'ip')
        for s in self.servers:
            sg.add_server(ip, s.port, s.conns_n)
        self.tempesta.config.add_sg(sg)

    def create_servers(self):
        """ Overrirde to create needed amount of upstream servers. """
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port)]

    def create_servers_helper(self, count, start_port=None, keep_alive=None):
        """ Helper function to spawn `count` servers in default configuration.
        """
        if start_port == None:
            start_port=tempesta.upstream_port_start_from()
        self.servers = []
        for i in range(count):
            self.servers.append(deproxy.Server(port=(start_port + i),
                                               keep_alive=keep_alive))

    def setUp(self):
        self.client = None
        self.tempesta = None
        self.servers = []
        self.tester = None
        tf_cfg.dbg(3) # Step to the next line after name of test case.
        tf_cfg.dbg(3, '\tInit test case...')
        self.create_tempesta()

    def tearDown(self):
        # Close client connection before stopping the TempestaFW.
        if self.client:
            self.client.close()
        if self.tempesta:
            self.tempesta.stop()
        if self.tester:
            self.tester.close_all()

    def assert_tempesta(self):
        """ Assert that tempesta had no errors during test. """
        msg = 'Tempesta have errors in processing HTTP %s.'
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 0,
                         msg=(msg % 'responses'))
        self.assertEqual(self.tempesta.stats.cl_msg_other_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_other_errors, 0,
                         msg=(msg % 'responses'))

    def create_tester(self, message_chain):
        self.tester = deproxy.Deproxy(message_chain, self.client, self.servers)

    def generic_test_routine(self, tempesta_defconfig, message_chains):
        """ Make necessary updates to configs of servers, create tempesta config
        and run the routine in you `test_*()` function.
        """
        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(tempesta_defconfig)

        self.create_servers()
        self.configure_tempesta()

        self.tempesta.start()
        self.create_client()

        self.create_tester(message_chains)
        self.tester.run()

        self.tempesta.get_stats()
        self.assert_tempesta()

if __name__ == '__main__':
    unittest.main()
