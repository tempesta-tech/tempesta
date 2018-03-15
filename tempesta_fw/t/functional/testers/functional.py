from __future__ import print_function
import unittest
import copy
import asyncore
from helpers import tf_cfg, control, tempesta, deproxy, stateful
from helpers.deproxy import ParseError

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class FunctionalTest(unittest.TestCase):

    tfw_clnt_msg_otherr = False

    def create_client(self):
        """ Override to set desired list of benchmarks and their options. """
        self.client = deproxy.Client()

    def create_tempesta(self):
        """ Normally no override is needed.
        Create controller for TempestaFW and add all servers to default group.
        """
        self.tempesta = control.Tempesta()

    def configure_tempesta(self):
        """ Add all servers to default server group with default scheduler. """
        sg = tempesta.ServerGroup('default')
        for s in self.servers:
            sg.add_server(s.ip, s.port, s.conns_n)
        self.tempesta.config.add_sg(sg)

    def create_servers(self):
        """ Overrirde to create needed amount of upstream servers. """
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port)]

    def create_servers_helper(self, count, start_port=None, keep_alive=None,
                              connections=None):
        """ Helper function to spawn `count` servers in default configuration.
        """
        if start_port is None:
            start_port = tempesta.upstream_port_start_from()
        self.servers = []
        for i in range(count):
            self.servers.append(deproxy.Server(port=(start_port + i),
                                               keep_alive=keep_alive,
                                               conns_n=connections))

    def create_tester(self):
        self.tester = deproxy.Deproxy(self.client, self.servers)

    def setUp(self):
        self.client = None
        self.client_state = None
        self.tempesta = None
        self.servers = []
        self.tester = None
        tf_cfg.dbg(3) # Step to the next line after name of test case.
        tf_cfg.dbg(3, '\tInit test case...')
        self.create_servers()
        self.create_tempesta()
        self.create_client()
        self.create_tester()

    def force_stop(self):
        # Close client connection before stopping the TempestaFW.
        if self.client:
            self.client.force_stop()

        if self.tempesta:
            self.tempesta.force_stop()

        if self.tester:
            self.tester.force_stop()

        for server in self.servers:
            server.force_stop()

        try:
            deproxy.finish_all_deproxy()
        except:
            print ('Unknown exception in stopping deproxy')


    def tearDown(self):
        # Close client connection before stopping the TempestaFW.
        if self.client:
            self.client.stop("Client")

        if self.tempesta:
            self.tempesta.stop("Tempesta")

        if self.tester:
            self.tester.stop("Tester")

        for server in self.servers:
            server.stop("Deproxy server")

        try:
            deproxy.finish_all_deproxy()
        except:
            print ('Unknown exception in stopping deproxy')

        for proc in [self.client, self.tempesta, self.tester]:
            if proc.state == stateful.STATE_ERROR:
                raise Exception("Error during stopping %s" %
                                proc.__class__.__name__)
        for server in self.servers:
            if server.state == stateful.STATE_ERROR:
                raise Exception("Error during stopping server")

    @classmethod
    def tearDownClass(cls):
        asyncore.close_all()

    def assert_tempesta(self):
        """ Assert that tempesta had no errors during test. """
        msg = 'Tempesta have errors in processing HTTP %s.'
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 0,
                         msg=(msg % 'responses'))
        if not self.tfw_clnt_msg_otherr:
            self.assertEqual(self.tempesta.stats.cl_msg_other_errors, 0,
                             msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_other_errors, 0,
                         msg=(msg % 'responses'))

    def generic_test_routine(self, tempesta_defconfig, message_chains):
        """ Make necessary updates to configs of servers, create tempesta config
        and run the routine in you `test_*()` function.
        """
        if message_chains and message_chains != []:
            self.tester.message_chains = message_chains

        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(tempesta_defconfig)
        self.configure_tempesta()

        tf_cfg.dbg(3, "Starting %i servers" % len(self.servers))
        for server in self.servers:
            server.start()

        self.tempesta.start()
        self.client.start()
        self.tester.start()
        tf_cfg.dbg(3, "\tStarting completed")

        try:
            self.tester.run()
        except ParseError as err:
            self.assertTrue(False, msg=str(type(err)))

        self.tempesta.get_stats()
        self.assert_tempesta()

if __name__ == '__main__':
    unittest.main()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
