from __future__ import print_function
import unittest
from helpers import deproxy, tf_cfg, tempesta
from testers import functional

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def sample_rule():
    request = deproxy.Request(
        "GET / HTTP/1.1\r\n"
        "Host: 10.0.10.2\r\n"
        "User-Agent: curl/7.53.1\r\n"
        "Accept: */*\r\n"
        "\r\n")
    response = deproxy.Response(
        "HTTP/1.0 200 OK\r\n"
        "Date: Tue, 07 Mar 2017 19:09:02 GMT\r\n"
        "Content-type: text/html\r\n"
        "Content-Length: 138\r\n"
        "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
        "Server: Tempesta FW/0.5.0-pre6\r\n"
        "Via: 1.0 tempesta_fw (Tempesta FW 0.5.0-pre6)\r\n"
        "\r\n"
        "<html>\r\n"
        "<head>\r\n"
        "  <title>An Example Page</title>\r\n"
        "</head>\r\n"
        "<body>\r\n"
        "  Hello World, this is a very simple HTML document.\r\n"
        "</body>\r\n"
        "</html>\r\n"
        "\r\n")
    fwd_request = deproxy.Request(
        "GET / HTTP/1.1\r\n"
        "Host: 10.0.10.2\r\n"
        "User-Agent: curl/7.53.1\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "Via: 1.1 tempesta_fw (Tempesta FW 0.5.0-pre6)\r\n"
        "X-Forwarded-For: 10.0.10.1\r\n"
        "\r\n")
    server_response = deproxy.Response(
        "HTTP/1.0 200 OK\r\n"
        "Server: SimpleHTTP/0.6 Python/3.6.0\r\n"
        "Date: Tue, 07 Mar 2017 19:09:02 GMT\r\n"
        "Content-type: text/html\r\n"
        "Content-Length: 138\r\n"
        "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
        "\r\n"
        "<html>\r\n"
        "<head>\r\n"
        "  <title>An Example Page</title>\r\n"
        "</head>\r\n"
        "<body>\r\n"
        "  Hello World, this is a very simple HTML document.\r\n"
        "</body>\r\n"
        "</html>\r\n")
    return deproxy.MessageChain(request=request, expected_response=response,
                                forwarded_request=fwd_request,
                                server_response=server_response)

def sample_rule_chunked():
    request = deproxy.Request(
        "GET / HTTP/1.1\r\n"
        "Host: 10.0.10.2\r\n"
        "User-Agent: curl/7.53.1\r\n"
        "Accept: */*\r\n"
        "\r\n")
    response = deproxy.Response(
        "HTTP/1.0 200 OK\r\n"
        "Date: Tue, 07 Mar 2017 19:09:02 GMT\r\n"
        "Content-type: text/html\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
        "Server: Tempesta FW/0.5.0-pre6\r\n"
        "Via: 1.0 tempesta_fw (Tempesta FW 0.5.0-pre6)\r\n"
        "\r\n"
        "4\r\n"
        "1234\r\n"
        "0\r\n"
        "\r\n")
    fwd_request = deproxy.Request(
        "GET / HTTP/1.1\r\n"
        "Host: 10.0.10.2\r\n"
        "User-Agent: curl/7.53.1\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "Via: 1.1 tempesta_fw (Tempesta FW 0.5.0-pre6)\r\n"
        "X-Forwarded-For: 10.0.10.1\r\n"
        "\r\n")
    server_response = deproxy.Response(
        "HTTP/1.0 200 OK\r\n"
        "Server: SimpleHTTP/0.6 Python/3.6.0\r\n"
        "Date: Tue, 07 Mar 2017 19:09:02 GMT\r\n"
        "Content-type: text/html\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
        "\r\n"
        "4\r\n"
        "1234\r\n"
        "0\r\n"
        "\r\n")
    return deproxy.MessageChain(request=request, expected_response=response,
                                forwarded_request=fwd_request,
                                server_response=server_response)

def defconfig():
    return 'cache 0;\n'


class DeproxyDummyTest(functional.FunctionalTest):
    """Test Deproxy, don't even start or setup TempestaFw in this test."""

    def setUp(self):
        self.client = None
        self.servers = []
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
        self.servers = [deproxy.Server(port=port, connections=1)]

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
