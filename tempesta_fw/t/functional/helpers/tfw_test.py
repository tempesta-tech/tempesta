from __future__ import print_function
import unittest, sys
from . import tf_cfg, control, tempesta

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Loader(unittest.TestCase):
    """ Test Suite to use HTTP benchmarkers as a clients. Can be used for
    functional testing of schedulers and stress testing for other components.
    """

    def create_clients(self):
        """ Override to set desired list of benchmarkers and their options. """
        self.clients = [ control.Wrk() ]

    def create_tempesta(self):
        """ Normally no override is needed.
        Create controller for TempestaFW and add all servers to default group.
        """
        self.tempesta = control.Tempesta()

    def configure_tempesta(self):
        """ Add all servers to default server group with default scheduler. """
        sg = tempesta.ServerGroup('default')
        ip = tf_cfg.cfg.get('Server', 'ip')
        for s in self.servers:
            sg.add_server(ip, s.config.port, s.conns_n)
        self.tempesta.config.add_sg(sg)

    def create_servers(self):
        """ Overrirde to create needed amount of upstream servers. """
        port = tempesta.upstream_port_start_from()
        self.servers = [ control.Nginx(listen_port = port) ]

    def create_servers_helper(self, count,
                              start_port = tempesta.upstream_port_start_from()):
        """ Helper function to spawn `count` servers in default configuration.

        See comment in Nginx.get_stats().
        """
        self.servers = []
        for i in range(count):
            self.servers.append(control.Nginx(listen_port = (start_port + i)))

    def setUp(self):
        tf_cfg.dbg(3) # Step to the next line after name of test case.
        tf_cfg.dbg(3, '\tInit test case...')
        self.create_clients()
        self.create_servers()
        self.create_tempesta()

    def tearDown(self):
        """ Carefully stop all servers. Error on stop will make next test fail,
        so mark test as failed even if eveything other is fine.
        """
        assert self.tempesta.stop(), \
            "Can't stop TempestaFW on %s" % self.tempesta.host
        assert control.servers_stop(self.servers), "Can't stop HTTP servers"

    def show_performance(self):
        if tf_cfg.v_level() < 2:
            return
        if tf_cfg.v_level() == 2:
            # Go to new line, don't mess up output.
            print()
        failed = 0
        req_total = err_total = 0
        for c in self.clients:
            ret, req, err = c.results()
            status = 'Ok'
            req_total += req
            err_total += err
            if not ret:
                status = 'Failed'
                failed += 1
            tf_cfg.dbg(3, '\tClient: finished: %s, errors: %d, requests: %d' %
                       (status, err, req))
        tf_cfg.dbg(
            2, '\tClients: finished OK %d out of %d, errors: %d, requests: %d' %
            (len(self.clients) - failed, len(self.clients), err_total,
             req_total))


    def assert_clients(self):
        """ Check benchmark result: no errors happen, no packet loss. """
        cl_req_cnt = 0
        for c in self.clients:
            ret, req, err = c.results()
            cl_req_cnt += req
            self.assertTrue(ret)
            self.assertEqual(err, 0)
        # Clients counts only complited requests and closes connections before
        # Tempesta can send responses. So Tempesta recieved requests count
        # differ from request count shown by clients. Didn't find any way how to
        # fix that.
        # Just check that difference is less than concurrent connections count.
        expected_diff = int(tf_cfg.cfg.get('General', 'concurrent_connections'))
        self.assertTrue((self.tempesta.stats.cl_msg_received - cl_req_cnt) <=
                        expected_diff)

    def assert_tempesta(self):
        """ Assert that tempesta had no errors during test. """
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 0)
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 0)
        # See comment in `assert_clients()`
        expected_err = int(tf_cfg.cfg.get('General', 'concurrent_connections'))
        self.assertTrue(self.tempesta.stats.cl_msg_other_errors <=
                        expected_err)
        self.assertTrue(self.tempesta.stats.srv_msg_other_errors <=
                        expected_err)

    def assert_servers(self):
        # Nothing to do for nginx in default configuration.
        pass

    def servers_get_stats(self):
        self.assertTrue(control.servers_get_stats(self.servers))

    def generic_test_routine(self, tempesta_defconfig):
        """ Make necessary updates to configs of servers, create tempesta config
        and run the routine in you `test_*()` function.
        """
        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(tempesta_defconfig)
        self.configure_tempesta()
        self.assertTrue(control.servers_start(self.servers))
        self.assertTrue(self.tempesta.start(),
                        msg="Can't start TempestaFW on %s" % self.tempesta.host)

        self.assertTrue(control.clients_run_parallel(self.clients))
        self.show_performance()

        # Tempesta statistics is valueble to client assertions.
        self.assertTrue(self.tempesta.get_stats())

        self.assert_clients()
        self.assert_tempesta()
        self.assert_servers()

if __name__ == '__main__':
	unittest.main()
