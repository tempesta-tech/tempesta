from __future__ import print_function
import unittest
import copy
import asyncore
from helpers import tf_cfg, control, tempesta, deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class FunctionalTest(unittest.TestCase):

    def create_client(self):
        """ Override to set desired list of benchmarks and their options. """
        self.client = deproxy.Client()

    def create_tempesta(self):
        """ Normally no override is needed.
        Create controller for TempestaFW and add all servers to default group.
        """
        self.tempesta = control.Tempesta()

    def configure_tempesta(self):
        """ Add all servers to default server group with default scheduler. """
        sg = tempesta.ServerGroup('default')
        for s in self.servers:
            sg.add_server(s.ip, s.port, s.conns_n)
        self.tempesta.config.add_sg(sg)

    def create_servers(self):
        """ Overrirde to create needed amount of upstream servers. """
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port)]

    def create_servers_helper(self, count, start_port=None, keep_alive=None,
                              connections=None):
        """ Helper function to spawn `count` servers in default configuration.
        """
        if start_port is None:
            start_port = tempesta.upstream_port_start_from()
        self.servers = []
        for i in range(count):
            self.servers.append(deproxy.Server(port=(start_port + i),
                                               keep_alive=keep_alive,
                                               conns_n=connections))

    def setUp(self):
        self.client = None
        self.tempesta = None
        self.servers = []
        self.tester = None
        tf_cfg.dbg(3) # Step to the next line after name of test case.
        tf_cfg.dbg(3, '\tInit test case...')
        self.create_tempesta()

    def tearDown(self):
        # Close client connection before stopping the TempestaFW.
        asyncore.close_all()
        if self.client:
            self.client.close()
        if self.tempesta:
            self.tempesta.stop()
        if self.tester:
            self.tester.close_all()

    @classmethod
    def tearDownClass(cls):
        asyncore.close_all()

    def assert_tempesta(self):
        """ Assert that tempesta had no errors during test. """
        msg = 'Tempesta have errors in processing HTTP %s.'
        self.assertEqual(self.tempesta.stats.cl_msg_parsing_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_parsing_errors, 0,
                         msg=(msg % 'responses'))
        self.assertEqual(self.tempesta.stats.cl_msg_other_errors, 0,
                         msg=(msg % 'requests'))
        self.assertEqual(self.tempesta.stats.srv_msg_other_errors, 0,
                         msg=(msg % 'responses'))

    def create_tester(self, message_chain):
        self.tester = deproxy.Deproxy(message_chain, self.client, self.servers)

    def generic_test_routine(self, tempesta_defconfig, message_chains):
        """ Make necessary updates to configs of servers, create tempesta config
        and run the routine in you `test_*()` function.
        """
        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(tempesta_defconfig)

        self.create_servers()
        self.configure_tempesta()

        self.tempesta.start()
        self.create_client()

        self.create_tester(message_chains)
        self.tester.run()

        self.tempesta.get_stats()
        self.assert_tempesta()


def base_message_chain(uri='/', method='GET'):
    """Base message chain. Looks like simple Curl request to Tempesta and
    response for it.

    Return new message chain.
    """
    request_headers = ['Host: %s' % tf_cfg.cfg.get('Tempesta', 'ip'),
                       'User-Agent: curl/7.53.1',
                       'Connection: keep-alive',
                       'Accept: */*']
    request = deproxy.Request.create(method, request_headers, uri=uri)

    fwd_request_headers = (
        request_headers +
        ['Via: 1.1 tempesta_fw (Tempesta FW %s)' % tempesta.version(),
         'X-Forwarded-For: %s' % tf_cfg.cfg.get('Client', 'ip')])
    fwd_request = deproxy.Request.create(method, fwd_request_headers, uri=uri)

    response_headers = ['Content-type: text/html',
                        'Connection: keep-alive',
                        'Content-Length: 138',
                        'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT']
    body = ("<html>\r\n"
            "<head>\r\n"
            "  <title>An Example Page</title>\r\n"
            "</head>\r\n"
            "<body>\r\n"
            "  Hello World, this is a very simple HTML document.\r\n"
            "</body>\r\n"
            "</html>\r\n")

    server_headers = response_headers + ['Server: Deproxy Server']
    server_response = deproxy.Response.create(
        200, server_headers, date=True, body=body)

    tempesta_headers = (
        response_headers +
        ['Server: Tempesta FW/%s' % tempesta.version(),
         'Via: 1.1 tempesta_fw (Tempesta FW %s)' % tempesta.version(),
         'Date: %s' % server_response.headers['Date']])
    tempesta_response = deproxy.Response.create(
        200, tempesta_headers, body=body)

    base_chain = deproxy.MessageChain(request=request,
                                      expected_response=tempesta_response,
                                      forwarded_request=fwd_request,
                                      server_response=server_response)

    return copy.copy(base_chain)


def base_message_chain_chunked(uri='/'):
    """Same as base_message_chain, but returns a copy of message chain with
    chunked body.
    """
    rule = base_message_chain()
    body = ("4\r\n"
            "1234\r\n"
            "0\r\n"
            "\r\n")

    for response in [rule.response, rule.server_response]:
        response.headers.delete_all('Content-Length')
        response.headers.add('Transfer-Encoding', 'chunked')
        response.body = body
        response.update()

    return rule

if __name__ == '__main__':
    unittest.main()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
