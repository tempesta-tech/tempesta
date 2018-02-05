"""
Tests for health monitoring functionality.
"""

from __future__ import print_function
import re
import copy
from testers import functional
from helpers import deproxy, chains, tempesta

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

CHAIN_TIMEOUT = 100

def make_response(st_code, expected=True):
    resp_headers = [
        'Content-Length: 0',
        'Connection: keep-alive'
    ]
    if expected:
        resp_headers += [
            'Server: Tempesta FW/%s' % tempesta.version(),
            'Via: 1.1 tempesta_fw (Tempesta FW %s)' % tempesta.version()
        ]
    else:
        resp_headers += ['Server: Deproxy Server']
    response = deproxy.Response.create(
        status=st_code,
        headers=resp_headers,
        date=deproxy.HttpMessage.date_time_string()
    )
    return response

def make_502_expected():
    response = deproxy.Response.create(
        status=502,
        headers=['Content-Length: 0', 'Connection: keep-alive'],
        date=deproxy.HttpMessage.date_time_string()
    )
    return response


class Stage(object):

    def __init__(self, tester, tempesta, client, chain, state, trans=False):
        self.trans_response = None
        self.chain = chain
        self.state = state
        self.tester = tester
        self.tempesta = tempesta
        self.client = client
        if trans:
            self.trans_response = make_response(200)

    def prepare(self):
        self.tester.current_chain = copy.copy(self.chain)
        self.tester.recieved_chain = deproxy.MessageChain.empty()
        self.client.clear()
        self.client.set_request(self.tester.current_chain.request)

    def check_transition(self, messages):
        expected = None
        if self.trans_response:
            expected = self.trans_response
        else:
            temp_chain = copy.copy(self.chain)
            expected = temp_chain.response
        expected.set_expected(expected_time_delta=CHAIN_TIMEOUT)
        self.assert_msg(
            expected == messages[1],
            (messages[0], messages[1], expected),
            trans=True
        )
        path = self.tester.get_server_path()
        stats, _ = self.tempesta.get_server_stats(path)
        s = r'HTTP availability\s+: (\d+)'
        m = re.search(s.encode('ascii'), stats)
        assert m, 'Cannot parse server stats: %s\n' % (stats)
        num = int(m.group(1))
        assert (num == 1 and self.state) or (num == 0 and not self.state), \
            ("Incorrect server HTTP availability state:\n"
             "\tnum = %d, self.state = %d\n"
             % (num, self.state))

    def check_results(self):
        result = None
        for message in ['response', 'fwd_request']:
            expected = getattr(self.tester.current_chain, message)
            received = getattr(self.tester.recieved_chain, message)
            if message == 'fwd_request' and not self.state:
                continue
            expected.set_expected(expected_time_delta=CHAIN_TIMEOUT)
            if (expected != received):
                result = (message, received, expected)
                break
        if not result:
            return True
        self.assert_msg(result[0] == 'response', result)
        return self.tester.next_stage(result)

    def assert_msg(self, cond, (message, received, expected), trans=False):
        trans_str = ' during transition' if trans else ''
        assert cond, \
            ("Received message (%s) does not suit expected one%s!\n\n"
             "\tReceieved:\n<<<<<|\n%s|>>>>>\n"
             "\tExpected:\n<<<<<|\n%s|>>>>>\n"
             % (message, trans_str, received, expected))


class StagedDeproxy(deproxy.Deproxy):

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        self.stages = []
        self.stages_n = 0
        self.stages_processed = 0
        self.current_stage = None

    def run(self):
        for _ in range(self.message_chains):
            self.prepare()
            self.loop()
            if not self.check_expectations():
                break

    def prepare(self):
        self.current_stage.prepare()

    def check_expectations(self):
        return self.current_stage.check_results()

    def assert_stages(self):
        assert self.stages_processed == self.stages_n, \
            ("Not all stages are passed: processed"
             " stages = %d, total stages count = %d"
             % (self.stages_processed, self.stages_n))

    def set_stages(self, stages):
        self.stages = stages
        self.stages_n = len(stages)
        self.current_stage = self.stages.pop(0)
        self.stages_processed = 1

    def next_stage(self, messages):
        if not self.stages:
            return False
        self.stages[0].check_transition(messages)
        self.current_stage = self.stages.pop(0)
        self.stages_processed += 1
        return True

    def get_server_path(self):
        return 'default/%s:%s' % (self.servers[0].ip, self.servers[0].port)


class TestHealthMonitor(functional.FunctionalTest):

    tfw_clnt_msg_otherr = True
    messages = 500000

    def create_tester(self, messages):
        """
        1. Create one message chain for enabled HM server's state:
        404 response will be returning until configured limit is
        reached (at this time HM will disable the server).
        2. Create another message chain - for disabled HM state:
        502 response will be returning by Tempesta until HM
        request will be sent to server after configured
        timeout (200 response will be returned and HM will
        enable the server).
        3. Create five Stages with alternated two message chains:
        so five transitions 'enabled=>disabled/disabled=>enabled'
        must be passed through.
        4. Each Stage must verify server's HTTP avalability state
        in 'check_transition()' method.
        """
        ch_enabled = chains.base(uri='/page.html')
        ch_enabled.server_response = make_response(404, expected=False)
        ch_enabled.response = make_response(404)
        ch_disabled = chains.base()
        ch_disabled.server_response = make_response(200, expected=False)
        ch_disabled.response = make_502_expected()
        self.tester = StagedDeproxy(messages, self.client, self.servers)
        self.tester.set_stages([
            Stage(
                self.tester, self.tempesta,
                self.client, ch_enabled,
                True
            ),
            Stage(
                self.tester, self.tempesta,
                self.client, ch_disabled,
                False
            ),
            Stage(
                self.tester, self.tempesta,
                self.client, ch_enabled,
                True, trans=True
            ),
            Stage(
                self.tester, self.tempesta,
                self.client, ch_disabled,
                False
            ),
            Stage(
                self.tester, self.tempesta,
                self.client, ch_enabled,
                True, trans=True
            )
        ])

    def create_servers(self):
        p = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=p, conns_n=3, hm='h_monitor1')]

    def assert_tempesta(self):
        self.tester.assert_stages()
        err_msg = 'Tempesta must have errors due' \
                  ' to inability to schedule request'
        functional.FunctionalTest.assert_tempesta(self)
        self.assertTrue(self.tempesta.stats.cl_msg_other_errors > 0,
                        msg=err_msg)

    def test(self):
        """Test health monitor functionality with all new configuration
        directives and options.
        """
        config = (
            'server_failover_http 404 300 10;\n'
            'health_check h_monitor1 {\n'
            'request "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";\n'
            'request_url "/page.html";\n'
            'resp_code 200;\n'
            'resp_crc32 3456;\n'
            'timeout 15;\n'
            '}\n'
            'cache 0;\n'
        )
        self.generic_test_routine(config, self.messages)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
