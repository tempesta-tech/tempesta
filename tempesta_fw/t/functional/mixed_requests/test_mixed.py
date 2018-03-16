from helpers import control, tempesta, tf_cfg
from testers import stress

import unittest
import mixed_test

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class GetRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "pipeline"
    pipelined_req = 7

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [control.Nginx(listen_port=port)]

class RealRequest(mixed_test.MixedRequests):
    """ Real GET request """
    script = "get_real"

class RealRequest2(mixed_test.MixedRequests):
    """ Real GET request 2"""
    script = "get_real_2"

class RealRequestPipeline(mixed_test.MixedRequests):
    """ Real pipelined GET request """
    script = "get_real_pipelined"
    pipelined_req = 3

class GetPostRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "get_post"
    pipelined_req = 5

    # during this test we send many bad post requests, so we get 400 responses
    def assert_clients(self):
        """ Check benchmark result: no errors happen, no packet loss. """
        cl_req_cnt = 0
        cl_conn_cnt = 0
        for c in self.clients:
            req, _, _, _ = c.results()
            cl_req_cnt += req
            cl_conn_cnt += c.connections * self.pipelined_req

        exp_min = cl_req_cnt
        exp_max = cl_req_cnt + cl_conn_cnt
        self.assertTrue(
            self.tempesta.stats.cl_msg_received >= exp_min and
            self.tempesta.stats.cl_msg_received <= exp_max
        )

class HeadGetRequests(mixed_test.MixedRequests):
    """ HEAD, GET requests """
    script = "head_get"
    pipelined_req = 2
    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [control.Nginx(listen_port=port)]

class EmptyPostRequests(mixed_test.MixedRequests):
    """ POST requests """
    script = "post_empty"

class SmallPostRequests(mixed_test.MixedRequests):
    """ POST requests """
    script = "post_small"

class BigPostRequests(mixed_test.MixedRequests):
    """ POST requests """
    script = "post_big"

class RarelyUsedRequests(mixed_test.MixedRequests):
    """ Rarely used requests """
    script = "mixed"
    pipelined_req = 7

class TraceRequests(mixed_test.MixedRequests):
    """ Rarely used requests """
    script = "trace"

    @unittest.expectedFailure
    def test(self):
        # nginx always send 405 for TRACE
        self.generic_test_routine(self.config)

class ConnectRequests(mixed_test.MixedRequests):
    """ Rarely used requests """
    script = "connect"
