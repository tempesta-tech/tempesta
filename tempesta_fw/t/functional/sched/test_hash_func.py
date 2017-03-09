"""
Hash scheduler pins resourses to specific servers and connections. Functional
test, check that the same server connection is used for the same resource.
"""

from __future__ import print_function
import unittest
from helpers import deproxy, tf_cfg, tempesta
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HashSchedulerTest(functional.FunctionalTest):
    """Hash scheduler functional test, check that the same server connection
    is used for the same resource.
    """

    messages = 100

    def configure_tempesta(self):
        functional.FunctionalTest.configure_tempesta(self)
        for sg in self.tempesta.config.server_groups:
            sg.sched = 'hash'

    def create_tester(self, message_chain):
        self.tester = HashTester(message_chain, self.client, self.servers)

    def chains(self):
        chain = functional.base_message_chain()
        return [chain for i in range (self.messages)]

    def test_hash_scheduler(self):
        self.generic_test_routine('cache 0;\n', self.chains())


class HashSchedulerFailoveredTest(HashSchedulerTest):
    """Same as HashSchedulerTest, but we will force servers to close connections
    time to time.
    """

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        keep_alive = self.messages // 10
        self.servers = [deproxy.Server(port=port, keep_alive=keep_alive)]


class HashTester(deproxy.Deproxy):

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        self.used_connection = None
        self.store_failovered = False

    def run(self):
        # Run loop to setup all the connections
        self.loop(0.1)
        self.used_connection = None
        self.store_failovered = True
        deproxy.Deproxy.run(self)
        self.store_failovered = False

    def register_srv_connection(self, connection):
        # Since only one server respond all requests with only one connection,
        # this new connection is failovered used one. Keep it.
        if self.store_failovered:
            self.used_connection = connection
        deproxy.Deproxy.register_srv_connection(self, connection)

    def recieved_forwarded_request(self, request, connection):
        if not self.used_connection:
            self.used_connection = connection
        else:
            assert self.used_connection is connection
        return deproxy.Deproxy.recieved_forwarded_request(self, request,
                                                          connection)
