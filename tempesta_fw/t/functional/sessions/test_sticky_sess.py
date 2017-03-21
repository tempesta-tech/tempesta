from __future__ import print_function
import sys
import unittest
import re
import copy
from helpers import deproxy, tempesta
from testers import functional
from . import cookies

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

defconfig = (
    'cache 0;\n'
    'sticky %s;\n'
    'sticky_secret "f00)9eR59*_/22";\n'
    '\n')

class TestSticky(functional.FunctionalTest):
    """ Functional test for using sticky sessions. """

    # No enforce
    config = defconfig % ''

    def create_servers(self):
        self.create_servers_helper(tempesta.servers_in_group(),
                                   connections=1)
    def configure_tempesta(self):
        functional.FunctionalTest.configure_tempesta(self)
        sg = self.tempesta.config.server_groups[0]
        if self.allow_failover:
            sg.options = 'sticky_sessions allow_failover;'
        else:
            sg.options = 'sticky_sessions;'

    def create_tester(self, message_chain):
        self.tester = TesterSticky(message_chain, self.client, self.servers)

    def chain_failover_ok(self):
        return self.tester.message_chains[1:]

    def chain_failover_fobbiden(self):
        chain = copy.copy(self.tester.message_chains[1])
        chain.no_forward()
        chain.response = cookies.make_502()
        return [chain for i in range(cookies.CHAIN_LENGTH)]

    def check_failover(self, new_message_chain_provider):
        self.generic_test_routine(self.config, [])
        message_chains = self.tester.message_chains
        # Shutdown server pinned to session and all its connections.
        self.previous_srv = self.tester.pinned_srv
        self.previous_srv.close()
        for conn in self.tester.srv_connections:
            if conn.server is self.previous_srv:
                conn.close()
        self.tester.pinned_srv = None
        self.tester.used_srv = None
        # Set new message chain after shutdown:
        self.tester.message_chains = new_message_chain_provider()
        self.tester.run()
        assert not self.tester.pinned_srv is self.previous_srv, \
            'Sticky session is forwarded to offline server'
        # Restore original message chains
        self.tester.message_chains = message_chains

    def check_back_online(self, new_message_chain_provider, restore):
        self.check_failover(new_message_chain_provider)
        # Return previous server back online.
        self.tester.srv_connections = (
            [conn for conn in self.tester.srv_connections if not conn.server is self.previous_srv])
        self.tester.servers = (
            [srv for srv in self.tester.servers if not srv is self.previous_srv])
        self.previous_srv = deproxy.Server(
            port=self.previous_srv.port,
            connections=self.previous_srv.conns_n)
        self.tester.servers.append(self.previous_srv)
        self.previous_srv.tester = self.tester

        if restore:
            self.tester.pinned_srv = self.previous_srv
            # Remove cookie negotiation, reuse old one.
            self.tester.message_chains = self.tester.message_chains[1:]
        else:
            self.tester.message_chains = new_message_chain_provider()
        self.tester.run()

    def test(self):
        """Simply sticky connections."""
        self.allow_failover = False
        self.generic_test_routine(self.config, [])

    def test_failover_fobbiden(self):
        """No Failover: if pinned server goes donw, return 502."""
        self.allow_failover = False
        self.check_failover(self.chain_failover_fobbiden)

    def test_failover(self):
        """With Failover: if pinned server goes down use new one."""
        self.allow_failover = True
        self.check_failover(self.chain_failover_ok)

    def test_back_online_no_failover(self):
        """No Failover: continue use pinned server if it back online."""
        self.allow_failover = False
        self.check_back_online(self.chain_failover_fobbiden, True)

    def test_back_online_after_failover(self):
        """With Failover: even if original server returned back proceed with
        the replacement server."""
        self.allow_failover = True
        self.check_back_online(self.chain_failover_ok, False)


class TestStickyEnforcedCookies(TestSticky):
    """ Functional test for using sticky sessions, cookies are enforced. """
    # Enforce
    config = defconfig % 'enforce'

    def create_tester(self, message_chain):
        self.tester = TesterStickyEnforcedCookies(
            message_chain, self.client, self.servers)


class TesterSticky(cookies.TesterUseCookies):

    def __init__(self, *args, **kwargs):
        cookies.TesterUseCookies.__init__(self, *args, **kwargs)
        self.pinned_srv = None
        self.used_srv = None

    def recieved_forwarded_request(self, request, connection):
        if not self.pinned_srv:
            self.pinned_srv = connection.server
        self.used_srv = connection.server
        return cookies.TesterUseCookies.recieved_forwarded_request(
            self, request, connection)

    def check_expectations(self):
        cookies.TesterUseCookies.check_expectations(self)
        assert self.pinned_srv is self.used_srv, \
            'Session is not Sticky, request forwarded to other server!'


class TesterStickyEnforcedCookies(cookies.TesterUseEnforcedCookies):

    def __init__(self, *args, **kwargs):
         cookies.TesterUseEnforcedCookies.__init__(self, *args, **kwargs)
         self.pinned_srv = None
         self.used_srv = None

    def recieved_forwarded_request(self, request, connection):
        if not self.pinned_srv:
            self.pinned_srv = connection.server
        self.used_srv = connection.server
        return cookies.TesterUseEnforcedCookies.recieved_forwarded_request(
            self, request, connection)

    def check_expectations(self):
        cookies.TesterUseCookies.check_expectations(self)
        assert self.pinned_srv is self.used_srv, \
            'Session is not Sticky, request forwarded to other server!'
