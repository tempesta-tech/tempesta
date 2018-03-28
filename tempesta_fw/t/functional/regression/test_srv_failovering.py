"""
Test Servers connections failovering.
"""

from __future__ import print_function
import random
import socket
import asyncore
from helpers import deproxy, tempesta
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class FailoveringTest(functional.FunctionalTest):
    """Spawn a lot of servers, close half on connections

    TODO: Check that TempestaFW keeps configured failovering intervals.
    """

    defconfig = ''
    timeout_limit = 5.0

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def create_tester(self):
        self.tester = FailoverTester(self.client, self.servers)

    def init(self):
        self.tempesta.config.set_defconfig(self.defconfig)

        self.create_servers()
        for server in self.servers:
            server.start()
        self.configure_tempesta()

        self.tempesta.start()
        self.create_client()
        self.client.start()
        # Message chains are not needed for the tester.
        self.create_tester()
        self.tester.start()

    def test_on_close(self):
        self.init()
        self.tester.loop(self.timeout_limit)
        self.assertTrue(self.tester.is_srvs_ready())

        self.tester.random_close()
        self.assertFalse(self.tester.is_srvs_ready())
        # Wait for connections failovering.
        self.tester.loop(self.timeout_limit)
        self.assertTrue(self.tester.is_srvs_ready())

    def test_on_shutdown(self):
        self.init()
        self.tester.loop(self.timeout_limit)
        self.assertTrue(self.tester.is_srvs_ready())

        self.tester.random_shutdown()
        self.assertFalse(self.tester.is_srvs_ready())
        # Wait for connections failovering.
        self.tester.loop(self.timeout_limit)
        self.assertTrue(self.tester.is_srvs_ready())

class ServerConnectRetriesFailoveringTest(FailoveringTest):
    """ Failovering with server_connect_retries option """

    defconfig = 'server_connect_retries 2;'

class ServerForwardRetriesFailoveringTest(FailoveringTest):
    """ Failovering with server_connect_retries option """

    defconfig = 'server_forward_retries 2;'

class ServerForwardTimeoutFailoveringTest(FailoveringTest):
    """ Failovering with server_connect_retries option """

    defconfig = 'server_forward_timeout 1;'

class ServerRetryNonidempotentFailoveringTest(FailoveringTest):
    """ Failovering with server_connect_retries option """

    defconfig = 'server_retry_nonidempotent;'

class ServerQueueSizeFailoveringTest(FailoveringTest):
    """ Failovering with server_connect_retries option """

    defconfig = 'server_queue_size 10;'

class NonidempotaentFailoveringTest(FailoveringTest):
    """ Failovering with server_connect_retries option """

    defconfig = 'nonidempotent GET prefix \"/users/\";'


class FailoverTester(deproxy.Deproxy):

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        self.expected_conns_n = sum([s.conns_n for s in self.servers])

    def register_srv_connection(self, connection):
        deproxy.Deproxy.register_srv_connection(self, connection)
        # Brake the loop wait if all connections are online.
        if self.expected_conns_n == len(self.srv_connections):
            raise asyncore.ExitNow

    def random_close(self):
        for _ in range(self.expected_conns_n // 4):
            conn = random.choice(self.srv_connections)
            if conn:
                conn.handle_close()

    def random_shutdown(self):
        for _ in range(self.expected_conns_n // 4):
            conn = random.choice(self.srv_connections)
            if conn:
                conn.socket.shutdown(socket.SHUT_RDWR)
                conn.handle_close()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
