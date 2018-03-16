"""
Test for 'Paired request missing, HTTP Response Splitting attack?' error
"""

from __future__ import print_function
from helpers import deproxy, tempesta, chains, tf_cfg, dmesg
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class PairingTest(functional.FunctionalTest):

    chains_size = 2
    send_to_close = chains_size / 2
    defconfig = ""

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port, conns_n=1)]

    def create_tester(self):
        message_chains = [chains.proxy() for _ in range(self.chains_size)]
        self.tester = PairingTester(self.client, self.servers,
                                    message_chains=message_chains)

    def prepare(self):
        self.tempesta.config.set_defconfig(self.defconfig)
        self.configure_tempesta()

        for server in self.servers:
            server.start()

        self.tempesta.start()
        self.client.start()
        self.tester.start()

    def test_disconnect_client(self):
        """Tempesta forwards requests from client to backend, but client
        disconnects before Tempesta received responses from backend. Responses
        must be evicted, no 'Paired request missing' messages are allowed.
        """
        self.prepare()
        self.tester.loop(0.5) # Let handle connects
        self.tester.send_reqs(self.send_to_close)
        self.tester.disconnect_clnt()
        self.tester.send_resps()
        self.assertEqual(dmesg.count_warnings(dmesg.WARN_SPLIT_ATTACK), 0,
                         msg=("Got '%s'" % dmesg.WARN_SPLIT_ATTACK))


class PairingTester(deproxy.Deproxy):

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        self.pause_srv = True
        self.message_chains_recv = [deproxy.MessageChain.empty()
                                    for _ in self.message_chains]
        self.last_resp = 0
        self.last_req = 0

    def send_reqs(self, req_n):
        e_req = self.last_req + req_n
        b_req = self.last_req

        for i in range(b_req, e_req):
            self.client.clear()
            self.client.set_request(self.message_chains[i])

            while self.client.request_buffer:
                self.loop(timeout=0.1)

    def send_resps(self):
        conn = self.srv_connections[0]
        for i in range(self.last_req):
            if self.message_chains_recv[i].fwd_request:
                conn.send_response(self.message_chains[i].server_response)
            else:
                break

    def recieved_response(self, response):
        self.message_chains_recv[self.last_resp].response = response
        self.last_resp += 1

    def recieved_forwarded_request(self, request, connection=None):
        self.message_chains_recv[self.last_req].fwd_request = request
        self.last_req += 1
        if self.pause_srv:
            return None
        return self.current_chain.server_response

    def disconnect_srv(self):
        conn = self.srv_connections[0]
        conn.handle_close()
        self.loop(timeout=0.1)

    def disconnect_clnt(self):
        self.client.handle_close()
        self.loop(timeout=0.1)
