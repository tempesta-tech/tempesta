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
    """ Test for cases with pipelined requests."""

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

    def run_test(self, ka_reqs):
        for s in self.servers:
            s.config.set_ka(ka_reqs)
        self.generic_test_routine('cache 0;\n')

    def test_unlimited_ka(self):
        self.run_test(sys.maxsize)

    @unittest.expectedFailure
    def test_low_ka(self):
        """Low keep_alive value, make the server to close after the limit
        is exhausted connection; thus Tempesta must generate 502 response.
        """
        self.run_test(50)

class PipelineFaultInjection(Pipeline):

    def create_tempesta(self):
        self.tempesta = control.TempestaFI('resp_alloc_err', True)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
