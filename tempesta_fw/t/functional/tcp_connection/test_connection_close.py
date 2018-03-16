"""
Tests for TCP connection closing.
"""

from __future__ import print_function
from testers import functional
from helpers import analyzer, deproxy, chains
import asyncore

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class CloseConnection(functional.FunctionalTest):
    """Regular connection closing."""

    def stop_and_close(self):
        '''To check the correctness of connection closing - we need to close
        it before stopping sniffer and analyzing sniffer's output (and throwing
        an exception in case of failure); so, we need to close Deproxy client
        and server connections in test_* function (not in tearDown).
        '''
        asyncore.close_all()
        self.client.stop()
        self.tempesta.stop()
        self.tester.stop()

    def create_sniffer(self):
        self.sniffer = analyzer.AnalyzerCloseRegular(self.tempesta.node,
                                                     self.tempesta.host,
                                                     node_close=False,
                                                     timeout=10)

    def assert_results(self):
        self.assertTrue(self.sniffer.check_results(),
                        msg='Incorrect FIN-ACK sequence detected.')

    def create_chains(self):
        return [chains.base(forward=True)]

    def run_sniffer(self):
        self.sniffer.start()
        self.generic_test_routine('cache 0;\n', self.create_chains())
        self.stop_and_close()
        self.sniffer.stop()

    def test(self):
        self.create_sniffer()
        self.run_sniffer()
        self.assert_results()


class CloseClientConnectiononInvalidReq(CloseConnection):
    """When an invalid request is received by Tempesta, it responds with 400
    and closes client connection.
    """

    def assert_tempesta(self):
        pass

    def create_chains(self):
        chain_200 = chains.base(forward=True)
        chain_200.request.body = ''.join(['Arbitrary data ' for _ in range(300)])
        chain_200.request.update()

        chain_400 = deproxy.MessageChain(
            request = deproxy.Request(),
            expected_response = chains.response_400())
        return [chain_200, chain_400]

    def create_sniffer(self):
        self.sniffer = analyzer.AnalyzerCloseRegular(self.tempesta.node,
                                                     self.tempesta.host,
                                                     timeout=10)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
