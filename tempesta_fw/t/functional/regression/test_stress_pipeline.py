"""
Pipeline stress testing.
"""

import sys
import unittest
from helpers import control, tempesta
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Pipeline(stress.StressTest):
    """ Test with pipelined requests."""

    # For pipeline test positive allowance must be corrected: it is
    # needed to multiply the number of misaccounted requests by
    # amount of pipeline requests from the 'wrk' lua script;
    # See comment on "positive allowance" in `StressTest.assert_clients()`
    pipelined_req = 7

    def create_clients(self):
        self.wrk = control.Wrk()
        self.wrk.set_script("pipeline")
        self.clients = [self.wrk]

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def test_pipelined_requests(self):
        self.generic_test_routine('cache 0;\n')


class PipelineFaultInjection(stress.StressTest):

    pipelined_req = 7
    cl_msg_errors = True

    def create_clients(self):
        self.wrk = control.Wrk()
        self.wrk.set_script("pipeline")
        self.clients = [self.wrk]

    def create_tempesta(self):
        self.tempesta = control.TempestaFI('resp_alloc_err', True)

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        server = control.Nginx(listen_port=port)
        server.conns_n = 1
        self.servers = [server]

    def assert_tempesta(self):
        """ Assert that tempesta must have errors for client messages
        in this test, as there is fault injected for memory allocation.
        """
        err_msg = 'Tempesta must have errors during response allocation fault'
        stress.StressTest.assert_tempesta(self)
        self.assertTrue(self.tempesta.stats.cl_msg_other_errors > 0,
                        msg=err_msg)

    def test_502_resp_fault(self):
        """Low keep_alive value, make the server to close after the limit
        is exhausted connection; thus Tempesta must generate 502 response.
        """
        for s in self.servers:
            s.config.set_ka(10)
        self.generic_test_routine('cache 0;\n')


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
