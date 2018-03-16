"""
Tests for health monitoring functionality.
"""

from __future__ import print_function
import re
import copy
import binascii
from testers import functional
from helpers import deproxy, chains, tempesta

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

CHAIN_TIMEOUT = 100

class Stage(object):

    def __init__(self, tester, client, chain, state, trans=None):
        self.trans_response = None
        self.chain = chain
        self.state = state
        self.tester = tester
        self.client = client
        self.trans_response = trans

    def prepare(self):
        self.tester.current_chain = copy.copy(self.chain)
        self.tester.recieved_chain = deproxy.MessageChain.empty()
        self.client.clear()
        self.client.set_request(self.tester.current_chain)

    def check_transition(self, messages):
        expected = None
        if self.trans_response:
            expected = copy.copy(self.trans_response)
        else:
            temp_chain = copy.copy(self.chain)
            expected = temp_chain.response
        expected.set_expected(expected_time_delta=CHAIN_TIMEOUT)
        self.assert_msg(
            expected == messages[1],
            (messages[0], messages[1], expected),
            trans=True
        )
        num = self.tester.srv_stats.get_server_health()
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
        self.srv_stats = None

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

    def configure(self, tempesta_obj, sg_name, stages):
        self.stages = stages
        self.stages_n = len(stages)
        self.current_stage = self.stages.pop(0)
        self.stages_processed = 1
        self.srv_stats = tempesta.ServerStats(tempesta_obj, sg_name,
                                              self.servers[0].ip,
                                              self.servers[0].port)

    def next_stage(self, messages):
        if not self.stages:
            return False
        self.stages[0].check_transition(messages)
        self.current_stage = self.stages.pop(0)
        self.stages_processed += 1
        return True


class TestHealthMonitor(functional.FunctionalTest):
    """ Test for health monitor functionality with stress option.
    Testing process is divided into several stages:
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
    must be passed through. Particular Stage objects are
    constructed in create_tester() method and then inserted
    into special StagedDeproxy tester.
    4. Each Stage must verify server's HTTP avalability state
    in 'check_transition()' method.
    """

    tfw_clnt_msg_otherr = True
    messages = 500000
    srv_group = 'srv_grp1'
    resp_codes_list = ['200']
    crc_check = False

    def create_chains(self):
        self.ch_enabled = chains.base(uri='/page.html')
        self.ch_enabled.server_response = chains.make_response(404, expected=False)
        self.ch_enabled.response = chains.make_response(404)
        self.ch_disabled = chains.base()
        # Make 200 status expected once for transition purpose.
        self.trans_resp = self.ch_disabled.response
        self.ch_disabled.response = chains.make_502_expected()

    def setUp(self):
        self.create_chains()
        if self.crc_check:
            resp_body = self.ch_disabled.server_response.body
            self.crc32 = hex(~binascii.crc32(resp_body, 0xffffffff) & 0xffffffff)
        functional.FunctionalTest.setUp(self)

    def get_config(self):
        crc32_conf = ''
        rcodes_conf = ''
        if self.crc_check:
            crc32_conf = 'resp_crc32 %s;\n' % self.crc32
        if self.resp_codes_list:
            rcodes_conf = 'resp_code %s;\n' % ' '.join(self.resp_codes_list)
        config = (
            'server_failover_http 404 300 10;\n'
            'cache 0;\n'
        )
        hm_config = ''.join(
            [
                'health_check h_monitor1 {\n',
                'request "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";\n',
                'request_url "/page.html";\n',
                'timeout 15;\n'
            ]
            + [crc32_conf] + [rcodes_conf] + ['}\n']
        )
        rules_config = ''.join(
            ['sched_http_rules {\n'] +
            ['match %s * * * ;\n' % self.srv_group] +
            ['}\n']
        )
        return config + hm_config + rules_config

    def create_tester(self):
        self.tester = StagedDeproxy(self.client, self.servers)
        self.tester.configure(self.tempesta, self.srv_group, [
            Stage(self.tester, self.client, self.ch_enabled, True),
            Stage(self.tester, self.client, self.ch_disabled, False),
            Stage(self.tester, self.client, self.ch_enabled, True,
                  trans=self.trans_resp),
            Stage(self.tester, self.client, self.ch_disabled, False),
            Stage(self.tester, self.client, self.ch_enabled, True,
                  trans=self.trans_resp)
        ])

    def create_servers(self):
        p = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=p, conns_n=3)]

    def configure_tempesta(self):
        sg = tempesta.ServerGroup(self.srv_group, hm='h_monitor1')
        for s in self.servers:
            sg.add_server(s.ip, s.port, s.conns_n)
        self.tempesta.config.add_sg(sg)

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
        self.generic_test_routine(self.get_config(), self.messages)


class TestHealthMonitorCRCOnly(TestHealthMonitor):
    resp_codes_list = None
    crc_check = True

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
