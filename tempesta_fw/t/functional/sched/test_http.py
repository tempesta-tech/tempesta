"""
Test fo http scheduler:
"""

from __future__ import print_function
import asyncore
from helpers import tempesta, deproxy, tf_cfg, chains
from testers import functional

class HttpRules(functional.FunctionalTest):
    """All requests must be forwarded to the right server groups according to
    sched_http_rules.
    """

    requests_n = 20

    config = (
        'cache 0;\n'
        '\n'
        'sched_http_rules {\n'
        '  match uri_p    uri       prefix  "/static";\n'
        '  match uri_s    uri       suffix  ".php";\n'
        '  match host_p   host      prefix  "static.";\n'
        '  match host_s   host      suffix  "tempesta-tech.com";\n'
        '  match host_e   host      eq      "foo.example.com";\n'
        '  match hdr_h_p  hdr_host  prefix  "bar.";\n'
        '  match hdr_h_e  hdr_host  eq      "buzz.natsys-lab.com";\n'
        '  match hdr_h_s  hdr_host  suffix  "natsys-lab.com";\n'
        '  match hdr_r_e  hdr_ref   eq      "example.com";\n'
        '  match hdr_r_s  hdr_ref   suffix  ".com";\n'
        '  match hdr_r_p  hdr_ref   prefix  "http://example.com";\n'
        '}\n'
        '\n')

    def make_chains(self, uri, extra_header=(None, None)):
        chain = chains.base(uri=uri)

        header, value = extra_header
        if not header is None:
            for req in [chain.request, chain.fwd_request]:
                req.headers.delete_all(header)
                req.headers.add(header, value)
                req.update()

        return [chain for _ in range(self.requests_n)]

    def create_client(self):
        # Client will be created for every server.
        for server in self.servers:
            server.client = deproxy.Client()

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        server_options = [
            (('uri_p'), ('/static/index.html'), None, None),
            (('uri_s'), ('/script.php'), None, None),
            (('host_p'), ('/'), ('host'), ('static.example.com')),
            (('host_s'), ('/'), ('host'), ('s.tempesta-tech.com')),
            (('host_e'), ('/'), ('host'), ('foo.example.com')),
            (('hdr_h_p'), ('/'), ('host'), ('bar.example.com')),
            (('hdr_h_s'), ('/'), ('host'), ('test.natsys-lab.com')),
            (('hdr_h_e'), ('/'), ('host'), ('buzz.natsys-lab.com')),
            (('hdr_r_e'), ('/'), ('referer'), ('example.com')),
            (('hdr_r_s'), ('/'), ('referer'), ('http://example.com')),
            (('hdr_r_p'), ('/'), ('referer'),
             ('http://example.com/cgi-bin/show.pl')),
            (('default'), ('/'), None, None)]

        for group, uri, header, value in server_options:
            # Dont need too lot connections here.
            server = deproxy.Server(port=port, conns_n=1)
            port += 1
            server.group = group
            server.chains = self.make_chains(uri=uri,
                                             extra_header=(header, value))
            self.servers.append(server)

    def configure_tempesta(self):
        """ Add every server to it's own server group with default scheduler.
        """
        for s in self.servers:
            sg = tempesta.ServerGroup(s.group)
            sg.add_server(s.ip, s.port, s.conns_n)
            self.tempesta.config.add_sg(sg)

    def create_tester(self):
        self.testers = []
        for server in self.servers:
            tester = HttpSchedTester(server.client, [server])
            tester.response_cb = self.response_recieved
            tester.message_chains = server.chains
            self.testers.append(tester)

    def routine(self):
        for i in range(self.requests_n):
            self.responses_recieved = 0
            for tester in self.testers:
                tester.configure(i)
            # Run asyncore loop with default timeout
            self.testers[0].loop()
            for tester in self.testers:
                tester.check_expectations()

    def init(self):
        self.tempesta.config.set_defconfig(self.config)

        self.configure_tempesta()
        for server in self.servers:
            server.start()

        self.tempesta.start()
        for server in self.servers:
            server.client.start()

        for tester in self.testers:
            tester.start()

    def test_scheduler(self):
        self.init()
        self.routine()

        self.tempesta.get_stats()
        self.assert_tempesta()

    def response_recieved(self):
        self.responses_recieved += 1
        if self.responses_recieved == len(self.servers):
            raise asyncore.ExitNow

    def setUp(self):
        self.testers = []
        functional.FunctionalTest.setUp(self)

    def tearDown(self):

        if self.tempesta:
            self.tempesta.stop()
        for tester in self.testers:
            tester.stop()
        for server in self.servers:
            server.client.stop("Deproxy client")
        for server in self.servers:
            server.stop("Deproxy server")


class HttpRulesBackupServers(HttpRules):

    config = (
        'cache 0;\n'
        '\n'
        'sched_http_rules {\n'
        '  match primary * * * backup=backup;\n'
        '}\n'
        '\n')

    def make_chains(self, empty=True):
        chain = None
        if empty:
            chain = deproxy.MessageChain.empty()
        else:
            chain = chains.base()
        return [chain for _ in range(self.requests_n)]

    def create_server_helper(self, group, port):
        server = deproxy.Server(port=port, conns_n=1)
        server.group = group
        server.chains = self.make_chains()
        return server

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.main_server = self.create_server_helper('primary', port)
        self.backup_server = self.create_server_helper('backup', port + 1)
        self.servers.append(self.main_server)
        self.servers.append(self.backup_server)

    def test_scheduler(self):
        self.init()
        # Main server is online, backup server must not recieve traffic.
        self.main_server.tester.message_chains = (
            self.make_chains(empty=False))
        self.backup_server.tester.message_chains = (
            self.make_chains(empty=True))
        self.routine()

        # Shutdown main server, responses must be forwarded to backup.
        self.main_server.tester.client.stop()
        self.main_server.stop()
        self.main_server.tester.message_chains = (
            self.make_chains(empty=True))

        self.backup_server.tester.message_chains = (
            self.make_chains(empty=False))
        self.routine()

        # Return main server back operational.
        self.testers.remove(self.main_server.tester)
        self.main_server = self.create_server_helper(
            group=self.main_server.group, port=self.main_server.port)
        tester = HttpSchedTester(deproxy.Client(), [self.main_server])
        tester.response_cb = self.response_recieved
        self.testers.append(tester)

        self.main_server.tester.message_chains = (
            self.make_chains(empty=False))
        self.backup_server.tester.message_chains = (
            self.make_chains(empty=True))

        self.main_server.start()
        self.main_server.tester.client.start()
        self.routine()

        # Check tempesta for no errors
        self.tempesta.get_stats()
        self.assert_tempesta()

    def response_recieved(self):
        self.responses_recieved += 1
        if self.responses_recieved == 1:
            raise asyncore.ExitNow


class HttpSchedTester(deproxy.Deproxy):

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)

    def configure(self, chain_n):
        if chain_n in range(len(self.message_chains)):
            self.current_chain = self.message_chains[chain_n]
        else:
            self.current_chain = deproxy.MessageChain.empty()

        self.recieved_chain = deproxy.MessageChain.empty()
        self.client.clear()
        self.client.set_request(self.current_chain.request)

    def recieved_response(self, response):
        # A lot of clients running, dont raise asyncore.ExitNow directly
        # instead call the
        self.recieved_chain.response = response
        self.response_cb()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
