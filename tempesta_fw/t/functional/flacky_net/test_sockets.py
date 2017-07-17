"""All sockets must be closed after Tempesta shutdown"""

from __future__ import print_function
import time
from helpers import control, tempesta, flacky, tf_cfg
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class CloseOnShutdown(stress.StressTest):

    config = (
        'cache 0;\n'
        '\n')

    def check_estab_conns(self, expect_estab=True, expext_failed=False):
        for server in self.servers:
            expected_conns = server.conns_n if expect_estab else 0
            estab_conns = flacky.get_sock_estab_count(
                self.tempesta.node, server.get_name())
            tot_conns = flacky.get_sock_count(
                self.tempesta.node, server.get_name())
            failed_conns = tot_conns - estab_conns

            self.assertEqual(
                expected_conns, estab_conns,
                msg=('Got unexpected count of established connections to server'
                     ' %s! Expected %d but got %d!'
                     % (server.get_name(), expected_conns, estab_conns)))

            if expext_failed is None:
                continue
            failed_conns_exp = server.conns_n if expext_failed else 0
            self.assertEqual(
                failed_conns, failed_conns_exp,
                msg=('Got %d opened but not established connections '
                     'to server %s' % (failed_conns, server.get_name())))

    def check_before_start(self):
        tf_cfg.dbg(3, 'Check that there is no opened sockets to servers '
                      'before start')
        self.check_estab_conns(expect_estab=False, expext_failed=False)

    def start_all(self):
        tf_cfg.dbg(3, 'Start servers and TempestaFW')
        self.tempesta.config.set_defconfig(self.config)
        self.configure_tempesta()
        control.servers_start(self.servers)
        self.tempesta.start()

    def check_after_start(self, allow_conns=True):
        time.sleep(1)
        tf_cfg.dbg(3, 'All connections must be established or failed.')
        self.check_estab_conns(expect_estab=allow_conns,
                               expext_failed=(not allow_conns))

    def check_after_stop(self):
        tf_cfg.dbg(3, 'All sockets must be closed after Tempesta Shutdown')
        self.tempesta.stop()
        self.check_estab_conns(expect_estab=False, expext_failed=False)

    def check_sockets(self, allow_conns=True):
        self.check_before_start()
        self.start_all()
        self.check_after_start(allow_conns)
        self.check_after_stop()

    def setUp(self):
        stress.StressTest.setUp(self)
        self.filter = None

    def tearDown(self):
        if self.filter:
            self.filter.clean_up()
        if hasattr(self, 'dummy_servers'):
            # No need to stop servers.
            if self.tempesta:
                self.tempesta.stop()
        else:
            stress.StressTest.tearDown(self)

    def init_filter(self):
        node = self.servers[0].node
        self.filter = flacky.Filter(node)
        self.filter.init_chains()
        self.filter_ports = range(tempesta.upstream_port_start_from(),
                                  self.servers[-1].config.port + 1)

    def test_reachable(self):
        """All servvers are reachable by TempestaFW, all connections will be
        successfuly established.
        """
        self.check_sockets()

    def test_filtered(self):
        """All servvers are behind firewall. All connection attempts will be
        silently dropped.
        """
        if not self.servers:
            return
        self.init_filter()
        self.filter.drop_on_ports(self.filter_ports)
        self.check_sockets(allow_conns=False)

    def force_reconnects(self):
        tf_cfg.dbg(3, 'Wait until connections would be reestablished, '
                      'send some requests and wait for kernel timers.')
        node = self.clients[0].node
        node.run_cmd('curl -m 180 %s || true' % self.clients[0].uri)

    def test_reachable_then_closed(self):
        """First servers are reachable, but after that the will be placed behind
        firewall.
        """
        if not self.servers:
            return
        self.init_filter()

        self.check_before_start()
        self.start_all()
        self.check_after_start(True)

        self.filter.drop_on_ports(self.filter_ports)
        self.force_reconnects()
        self.check_after_start(False)
        self.check_after_stop()

    def test_not_started_server(self):
        """HTTP Server is not started on available server."""
        self.check_before_start()

        self.tempesta.config.set_defconfig(self.config)
        self.configure_tempesta()
        self.tempesta.start()
        # We didn't start servers, set a flag for tearDown
        self.dummy_servers = True

        # Check after start. Special case here: connections will be closed
        # immediately or after some time. and we cant predict exact number of
        # existing but not connected sockets. This mostly depends on Server
        # node. It is local for Tempesta node, sockets will be closed
        # immediately.
        self.check_estab_conns(expect_estab=False, expext_failed=None)
        self.check_after_stop()

    def test_sometimes_available(self):
        """Start when server behind firewall, swich firewall off and on again.
        """
        # Start when server behind firewall
        self.init_filter()
        self.filter.drop_on_ports(self.filter_ports)
        self.check_before_start()
        self.start_all()
        self.check_after_start(False)

        self.force_reconnects()
        self.check_after_start(False)

        # Swich firewall off
        self.filter.clean()
        self.force_reconnects()
        self.check_after_start(True)

        # Swich firewall on
        self.filter.drop_on_ports(self.filter_ports)
        self.force_reconnects()
        self.check_after_start(False)

        self.check_after_stop()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
