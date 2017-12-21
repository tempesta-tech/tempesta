from __future__ import print_function
import unittest
from helpers import tf_cfg, control, tempesta, stateful

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class StressTest(unittest.TestCase):
    """ Test Suite to use HTTP benchmarks as a clients. Can be used for
    functional testing of schedulers and stress testing for other components.
    """

    pipelined_req = 1
    tfw_msg_errors = False

    def create_clients(self):
        """ Override to set desired list of benchmarks and their options. """
        self.clients = [control.Wrk()]

    def create_tempesta(self):
        """ Normally no override is needed.
        Create controller for TempestaFW and add all servers to default group.
        """
        self.tempesta = control.Tempesta()

    def configure_tempesta(self):
        """ Add all servers to default server group with default scheduler. """
        sg = tempesta.ServerGroup('default')
        for s in self.servers:
            sg.add_server(s.ip, s.config.port, s.conns_n)
        self.tempesta.config.add_sg(sg)

    def create_servers(self):
        """ Overrirde to create needed amount of upstream servers. """
        port = tempesta.upstream_port_start_from()
        self.servers = [control.Nginx(listen_port=port)]

    def create_servers_helper(self, count, start_port=None):
        """ Helper function to spawn `count` servers in default configuration.

        See comment in Nginx.get_stats().
        """
        if start_port is None:
            start_port = tempesta.upstream_port_start_from()
        self.servers = []
        for i in range(count):
            self.servers.append(control.Nginx(listen_port=(start_port + i)))

    def setUp(self):
        # Init members used in tearDown function.
        self.tempesta = None
        self.servers = []
        tf_cfg.dbg(3) # Step to the next line after name of test case.
        tf_cfg.dbg(3, '\tInit test case...')
        self.create_clients()
        self.create_servers()
        self.create_tempesta()

    def force_stop(self):
        """ Forcefully stop all servers. """
        # Call functions only if variables not None: there might be an error
        # before tempesta would be created.

        if self.tempesta:
            tf_cfg.dbg(2, "Stopping tempesta")
            self.tempesta.force_stop()

        if self.servers:
            tf_cfg.dbg(2, "Stopping servers")
            control.servers_force_stop(self.servers)

    def tearDown(self):
        """ Carefully stop all servers. Error on stop will make next test fail,
        so mark test as failed even if everything other is fine.
        """
        # Call functions only if variables not None: there might be an error
        # before tempesta would be created.

        if self.tempesta:
            tf_cfg.dbg(2, "Stopping tempesta")
            self.tempesta.stop()

        if self.servers:
            tf_cfg.dbg(2, "Stopping servers")
            control.servers_stop(self.servers)

        if self.tempesta.state == stateful.STATE_ERROR:
            raise Exception("Error during stopping tempesta")
        for server in self.servers:
            if server.state == stateful.STATE_ERROR:
                raise Exception("Error during stopping servers")

    def show_performance(self):
        if tf_cfg.v_level() < 2:
            return
        if tf_cfg.v_level() == 2:
            # Go to new line, don't mess up output.
            tf_cfg.dbg(2)
        req_total = err_total = 0
        for c in self.clients:
            req, err = c.results()
            req_total += req
            err_total += err
            tf_cfg.dbg(3, '\tClient: errors: %d, requests: %d' % (err, req))
        tf_cfg.dbg(
            2, '\tClients in total: errors: %d, requests: %d' %
            (err_total, req_total))


    def assert_clients(self):
        """ Check benchmark result: no errors happen, no packet loss. """
        cl_req_cnt = 0
        cl_conn_cnt = 0
        for c in self.clients:
            req, err = c.results()
            cl_req_cnt += req
            cl_conn_cnt += c.connections * self.pipelined_req
            self.assertEqual(err, 0, msg='HTTP client detected errors')
        exp_min = cl_req_cnt
        # Positive allowance: this means some responses are missed by the client.
        # It is believed (nobody actually checked though...) that wrk does not
        # wait for responses to last requests in each connection before closing
        # it and does not account for those requests.
        # So, [0; concurrent_connections] responses will be missed by the client.
        exp_max = cl_req_cnt + cl_conn_cnt
        self.assertTrue(
            self.tempesta.stats.cl_msg_received >= exp_min and
            self.tempesta.stats.cl_msg_received <= exp_max
        )

    def assert_tempesta(self):
        """ Assert that tempesta had no errors during test. """
        msg = 'Tempesta have errors in processing HTTP %s.'
        cl_conn_cnt = 0
        for c in self.clients:
            cl_conn_cnt += c.connections
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 0,
                         msg=(msg % 'responses'))
        if self.tfw_msg_errors:
            return

        self.assertTrue(self.tempesta.stats.cl_msg_other_errors <= 0,
                        msg=(msg % 'requests'))
        # See comment on "positive allowance" in `assert_clients()`
        expected_err = cl_conn_cnt
        self.assertTrue(self.tempesta.stats.srv_msg_other_errors <= expected_err,
                        msg=(msg % 'responses'))

    def assert_servers(self):
        # Nothing to do for nginx in default configuration.
        # Implementers of this method should take into account the deficiency
        # of wrk described above.
        pass

    def servers_get_stats(self):
        control.servers_get_stats(self.servers)

    def generic_test_routine(self, tempesta_defconfig):
        """ Make necessary updates to configs of servers, create tempesta config
        and run the routine in you `test_*()` function.
        """
        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(tempesta_defconfig)
        self.configure_tempesta()
        control.servers_start(self.servers)
        self.tempesta.start()

        control.clients_run_parallel(self.clients)
        self.show_performance()

        # Tempesta statistics is valuable to client assertions.
        self.tempesta.get_stats()

        self.assert_clients()
        self.assert_tempesta()
        self.assert_servers()

if __name__ == '__main__':
    unittest.main()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
