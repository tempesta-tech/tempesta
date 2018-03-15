"""
Test TempestaFW shutdown when multiple connections between TempestaFW and
clients/servers are established.
"""

from __future__ import print_function
from helpers import deproxy, tempesta, remote
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ShutdownTest(functional.FunctionalTest):
    """Spawn a lot of clients, a lot of servers, make some requests but do not
    send responses. Shutdown TempestaFW while all the connections are up.
    No crushes must happen.

    TODO: Add test with half of the servers blocked by netfilter.
    """

    def setUp(self):
        self.clients = []
        functional.FunctionalTest.setUp(self)

    def tearDown(self):
        if self.tempesta:
            self.tempesta.stop("Tempesta")
        if self.tester:
            self.tester.stop("Tester")

    def create_tester(self):
        pass

    def create_client(self):
        for _ in range(100):
            self.clients.append(deproxy.Client())

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group())

    def init(self):
        defconfig = 'cache 0;\n'
        self.tempesta.config.set_defconfig(defconfig)
        self.create_servers()
        for server in self.servers:
            server.start("Server")
        self.configure_tempesta()
        self.tempesta.start("Tempesta")
        self.create_client()
        self.tester = ShutdownTester(self.clients, self.servers)
        for client in self.clients:
            client.start("Client")
        self.tester.start("Tester")

    def test_shutdown(self):
        self.init()
        # Run loop for small time to allow clients and servers process socket
        # events.
        self.tester.loop()
        self.tempesta.stop("Tempesta")
        # Run random command on remote node to see if it is still alive.
        remote.tempesta.run_cmd('uname')

    def test_shutdown_with_traffic(self):
        self.init()
        # Run loop for small time to allow clients and servers process socket
        # events.
        self.tester.run()
        self.tempesta.stop("Tempesta")
        # Run requests once more time.
        self.tester.run()
        # Run random command on remote node to see if it is still alive.
        remote.tempesta.run_cmd('uname')


class ShutdownTester(deproxy.Deproxy):

    def __init__(self, clients, servers):
        deproxy.Deproxy.__init__(self, None, servers, register=False)
        self.clients = clients
        request = deproxy.Request(
            "GET / HTTP/1.1\r\n"
            "Host: host\r\n"
            "User-Agent: curl/7.53.1\r\n"
            "\r\n")
        response = deproxy.Response()
        self.current_chain = deproxy.MessageChain(request, response,
                                                  server_response=response)
        self.register_tester()
        self.stop_procedures = [self.close_all]

    def register_tester(self):
        for client in self.clients:
            client.set_tester(self)
        for server in self.servers:
            server.set_tester(self)

    def run(self):
        self.recieved_chain = deproxy.MessageChain.empty()
        for client in self.clients:
            client.clear()
            client.set_request(self.current_chain)
        self.loop()

    def close_all(self):
        for client in self.clients:
            client.stop("Client")
        servers = [server for server in self.servers]
        for server in servers:
            server.stop("Server")

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
