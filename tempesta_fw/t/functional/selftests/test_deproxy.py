from __future__ import print_function
from helpers import deproxy, tf_cfg, tempesta
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def sample_rule():
    return functional.base_message_chain()

def sample_rule_chunked():
    return functional.base_message_chain_chunked()

def defconfig():
    return 'cache 0;\n'


class DeproxyDummyTest(functional.FunctionalTest):
    """Test Deproxy, don't even start or setup TempestaFw in this test."""

    def setUp(self):
        self.client = None
        self.servers = []
        self.tester = None
        tf_cfg.dbg(3) # Step to the next line after name of test case.
        tf_cfg.dbg(3, '\tInit test case...')

    def tearDown(self):
        if self.client:
            self.client.close()
        if self.tester:
            self.tester.close_all()

    def create_clients(self):
        port = tempesta.upstream_port_start_from()
        self.client = deproxy.Client(port=port, host='Client')

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port, conns_n=1)]

    def routine(self, message_chains):
        self.create_servers()
        self.create_clients()
        self.create_tester(message_chains)
        self.tester.run()

    def test_deproxy_one_chain(self):
        chain = sample_rule()
        # In this test we do not have proxy
        chain.response = chain.server_response
        chain.fwd_request = chain.request

        message_chains = [chain]
        self.routine(message_chains)


class DeproxyTest(functional.FunctionalTest):

    def test_deproxy_one_chain(self):
        message_chains = [sample_rule()]
        self.generic_test_routine(defconfig(), message_chains)


class DeproxyChunkedTest(functional.FunctionalTest):

    def test_deproxy_one_chain(self):
        message_chains = [sample_rule_chunked()]
        self.generic_test_routine(defconfig(), message_chains)


class DeproxyTestFailOver(DeproxyTest):

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port, keep_alive=1)]

    def create_tester(self, message_chain):

        class DeproxyFailOver(deproxy.Deproxy):
            def check_expectations(self):
                # We closed server connection after response. Tempesta must
                # failover the connection. Run loop with small timeout
                # once again to pocess events.
                self.loop(0.1)
                assert self.is_srvs_ready(), 'Failovering failed!'
                deproxy.Deproxy.check_expectations(self)

        self.tester = DeproxyFailOver(message_chain, self.client, self.servers)
