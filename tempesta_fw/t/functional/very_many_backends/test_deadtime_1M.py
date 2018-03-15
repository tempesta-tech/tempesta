__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from helpers import control, tempesta, nginx, tf_cfg
from helpers import deproxy, chains, remote, stateful
from testers import stress
from . import multi_backend

import sys
import os
import time
import select
import asyncore
import multiprocessing

class DeadtimeClient(stateful.Stateful):
    """ Client for deadtime measuring """
    long_times = 0
    wait = False

    def __init__(self, uri='/', max_deadtime=1, timeout=20):
        self.uri = uri
        self.timeout = timeout
        self.max_deadtime = max_deadtime
        self.stop_procedures = [self.__stop]
        self.client = deproxy.Client()
        self.client.set_tester(self)
        self.message_chains = [chains.base()]
        self.finish_event = multiprocessing.Event()

    def clear_stats(self):
        self.long_times = 0

    def run_start(self):
        self.proc = multiprocessing.Process(target=self.run,
                                            args=(self.finish_event,))
        self.proc.start()

    def __stop(self):
        # 'if' is required for force_stop
        if self.proc:
            self.finish_event.set()
            self.proc.join()
            self.long_times = self.proc.exitcode
        self.proc = None

    def loop(self, timeout):
        """Poll for socket events no more than `timeout` seconds."""
        self.wait = True
        try:
            eta = time.time() + timeout
            s_map = asyncore.socket_map

            if hasattr(select, 'poll'):
                poll_fun = asyncore.poll2
            else:
                poll_fun = asyncore.poll

            while self.wait and (eta > time.time()):
                poll_fun(eta - time.time(), s_map)
        except asyncore.ExitNow:
            pass

    def recieved_response(self, response):
        self.wait = False

    def is_srvs_ready(self):
        return True

    def request(self, timeout):
        for self.current_chain in self.message_chains:
            self.recieved_chain = deproxy.MessageChain.empty()
            self.client.clear()
            self.client.set_request(self.current_chain.request)
            self.loop(timeout)

    def run(self, finish_event):
        num_req = 0
        long_times = 0
        short_times = 0
        max_delay = 0
        min_delay = -1
        start_time = time.time()
        success_time = start_time
        curtime = start_time
        self.client.start()
        while (curtime - start_time < self.timeout or self.timeout < 0) and \
              not finish_event.is_set():
            self.request(self.timeout)
            curtime = time.time()
            delay = curtime - success_time
            if delay > self.max_deadtime:
                long_times += 1
            else:
                short_times += 1
            if delay > max_delay:
                max_delay = delay
            if delay < min_delay or min_delay == -1:
                min_delay = delay
            success_time = curtime
            num_req += 1
            if num_req % 10000 == 0:
                tf_cfg.dbg(3, "%i requests done" % num_req)

        delay = curtime - success_time
        if delay > self.max_deadtime:
            long_times += 1
        if delay > max_delay:
                max_delay = delay
        tf_cfg.dbg(3, "number of requests shorter than  1 s: %i" % short_times)
        tf_cfg.dbg(3, "number of requests longer than 1 s: %i" % long_times)
        tf_cfg.dbg(3, "max request time: %f" % max_delay)
        tf_cfg.dbg(3, "min request time: %f" % min_delay)
        if finish_event.is_set():
            tf_cfg.dbg(3, "Finish event recieved")
        else:
            tf_cfg.dbg(3, "No finish event recieved")
        self.client.stop()
        sys.exit(long_times)

class DontModifyBackend(stress.StressTest):
    """ 1 backend in server group """
    num_attempts = 10
    max_deadtime = 2
    num_extra_interfaces = 8
    num_extra_ports = 32
    ips = []
    normal_servers = 0
    config = "cache 0;\n"
    base_port = 16384
    wait = True
    client = None
    configurator = None

    def setUp(self):
        tf_cfg.dbg(2, "Creating interfaces")
        self.interface = tf_cfg.cfg.get('Server', 'aliases_interface')
        self.base_ip = tf_cfg.cfg.get('Server',   'aliases_base_ip')
        self.ips = multi_backend.create_interfaces(self.interface,
                           self.base_ip, self.num_extra_interfaces + 1)
        stress.StressTest.setUp(self)

    def tearDown(self):
        has_base_excpt = False
        # stopping client
        if self.client != None:
            self.client.stop()
        # stopping tempesta and servers
        try:
            stress.StressTest.tearDown(self)
        except Exception as exc:
            has_base_excpt = True
            excpt = exc
        tf_cfg.dbg(2, "Removing interfaces")
        for ip in self.ips:
            multi_backend.remove_interface(self.interface, ip)
        self.ips = []
        if has_base_excpt:
            raise excpt
        if self.client.state == stateful.STATE_ERROR:
            raise Exception("Error while stopping client")

    def configure_tempesta(self):
        """ Configure tempesta 1 port in group """
        sg = tempesta.ServerGroup('default')
        server = self.servers[0]
        sg.add_server(server.ip, server.config.listeners[0].port,
                      server.conns_n)
        self.tempesta.config.add_sg(sg)
        self.append_extra_server_groups()

    def append_server_group(self, id):
        sg = tempesta.ServerGroup('new-%i' % id)
        server = self.servers[1]
        for listener in server.config.listeners:
            sg.add_server(server.ip, listener.port, server.conns_n)
        self.tempesta.config.add_sg(sg)

    def append_extra_server_groups(self):
        sgid = 0
        for ifc in range(self.num_extra_interfaces):
            server = self.servers[self.extra_servers_base + ifc]
            for listener in server.config.listeners:
                sg = tempesta.ServerGroup('extra-%i' % sgid)
                sg.add_server(server.ip, listener.port, server.conns_n)
                self.tempesta.config.add_sg(sg)
                sgid += 1

    def create_clients(self):
        """ Override to set desired list of benchmarks and their options. """
        self.client = DeadtimeClient(timeout=-1)

    def setup_nginx_config(self, config):
        config.enable_multi_accept()
        config.set_worker_connections(32768)
        config.set_workers(4096)
        config.set_worker_rlimit_nofile(16384)
        config.set_ka(timeout = 180)
        for listener in config.listeners:
            listener.backlog = 9000
        config.build_config()
        return

    def create_servers(self):
        self.servers = []
        # default server
        defport=tempesta.upstream_port_start_from()
        server = multi_backend.NginxMP(listen_port=defport)
        self.setup_nginx_config(server.config)
        self.servers.append(server)

        server = multi_backend.NginxMP(listen_port=self.base_port,
                               ports_n=self.num_attempts,
                               listen_ip=self.ips[0])
        self.setup_nginx_config(server.config)
        self.servers.append(server)

        self.extra_servers_base = len(self.servers)
        for ifc in range(self.num_extra_interfaces):
            server = multi_backend.NginxMP(listen_port=self.base_port,
                                   ports_n=self.num_extra_ports,
                                   listen_ip=self.ips[ifc + 1])
            self.setup_nginx_config(server.config)
            self.servers.append(server)

    def pre_test(self):
        if remote.server != remote.tempesta:
            remote.server.run_cmd("sysctl -w net.core.somaxconn=8192")
            remote.server.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")
        # tempesta somaxconn sysctl setups from tempesta.sh
        remote.tempesta.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")
        if remote.client != remote.tempesta:
            remote.client.run_cmd("sysctl -w net.core.somaxconn=8192")
            remote.client.run_cmd("sysctl -w net.ipv4.tcp_max_orphans=1000000")

        for server in self.servers:
            server.start()

        self.tempesta.config.set_defconfig(self.config)
        self.configure_tempesta()
        self.tempesta.start()
        self.client.start()

    def post_test(self):
        self.client.stop()
        self.assert_clients()

    def assert_clients(self):
        msg = "Reconfiguration took too long time: " \
              " server group was unavailable more than 1s"
        self.assertEqual(self.client.long_times, 0, msg)

    def reconfigure_tempesta(self, i):
        self.append_server_group(i)
        self.tempesta.reload()

    def test(self):
        self.pre_test()
        time.sleep(self.num_attempts * self.max_deadtime)
        self.post_test()

class AddingBackendNewSG(DontModifyBackend):

    def test(self):
        self.pre_test()
        for i in range(self.num_attempts):
            tf_cfg.dbg(2, "Adding server group #%i" % i)
            self.append_server_group(i)
            t1 = time.time()
            self.tempesta.reload()
            t2 = time.time()
            tf_cfg.dbg(4, "tempesta.reload() %f s" % (t2-t1))
            time.sleep(self.max_deadtime)
        self.post_test()

class RemovingBackendSG(DontModifyBackend):
    num_attempts = 10
    max_deadtime = 1

    def remove_server_group(self, id):
        self.tempesta.config.remove_sg("new-%i" % id)

    def configure_tempesta(self):
        """ Configure tempesta 1 port in group """
        sg = tempesta.ServerGroup('default')
        server = self.servers[0]
        sg.add_server(server.ip, server.config.listeners[0].port,
                      server.conns_n)
        self.tempesta.config.add_sg(sg)
        self.append_extra_server_groups()
        for i in range(self.num_attempts):
            self.append_server_group(i)
        return

    def test(self):
        self.pre_test()
        for i in range(self.num_attempts):
            tf_cfg.dbg(2, "Removing server group #%i" % i)
            self.remove_server_group(i)
            t1 = time.time()
            self.tempesta.reload()
            t2 = time.time()
            tf_cfg.dbg(4, "tempesta.reload() %f s" % (t2-t1))
            time.sleep(self.max_deadtime)
        self.post_test()

class ChangingSG(DontModifyBackend):
    num_attempts = 10
    max_deadtime = 1
    def_sg = None

    def configure_tempesta(self):
        """ Configure tempesta 1 port in group """
        sg = tempesta.ServerGroup('default')
        self.def_sg = sg
        server = self.servers[0]
        sg.add_server(server.ip, server.config.listeners[0].port,
                      server.conns_n)
        self.tempesta.config.add_sg(sg)
        self.append_extra_server_groups()
        return

    def test(self):
        self.pre_test()
        for i in range(self.num_attempts):
            tf_cfg.dbg(2, "Adding new server to default group")
            server = self.servers[1]
            self.def_sg.add_server(server.ip,
                server.config.listeners[i].port, server.conns_n)
            t1 = time.time()
            self.tempesta.reload()
            t2 = time.time()
            tf_cfg.dbg(4, "tempesta.reload() %f s" % (t2-t1))
            time.sleep(self.max_deadtime)
        self.post_test()

