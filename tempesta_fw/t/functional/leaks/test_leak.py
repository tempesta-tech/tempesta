"""
Testing for memory leaks
"""

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import unittest
import re
from time import sleep

from testers import stress
from helpers import tf_cfg, control, tempesta, remote

def drop_caches():
    """ Drop caches """
    remote.tempesta.run_cmd("echo 3 > /proc/sys/vm/drop_caches")
    sleep(1)

def file_exists(remote_file):
    """ Check existance of file on Tempesta host """
    check_cmd = "if [ -e %s ]; then echo -n yes; fi" % remote_file
    [stdout, stderr] = remote.tempesta.run_cmd(check_cmd)
    if stdout != "yes":
        return False
    return True

def has_kmemleak():
    """ Check presence of kmemleak """
    return file_exists("/sys/kernel/debug/kmemleak")

def has_meminfo():
    """ Check presence of meminfo """
    return file_exists("/proc/meminfo")

def read_kmemleaks():
    """ Get amount of kmemleak records """
    kmemleakfile = "/sys/kernel/debug/kmemleak"
    if not has_kmemleak():
        tf_cfg.dbg(1, "kmemleak file does not exists")
        return -1
    cmd = "cat %s | grep \"unreferenced object\" | wc -l" % kmemleakfile
    [stdout, stderr] = remote.tempesta.run_cmd(cmd)
    return int(stdout)

def get_memory_line(name):
    """ Get value from /proc/meminfo """
    if not has_meminfo():
        return -1
    [stdout, stderr] = remote.tempesta.run_cmd("cat /proc/meminfo")
    line = re.search("%s:[ ]+([0-9]+)" % name, stdout)
    if line:
        return int(line.group(1))
    return -1

def slab_memory():
    """ Get amount of slab used memory """
    drop_caches()
    slabmem = get_memory_line("Slab")
    return slabmem

def used_memory():
    """ Measure total memory usage """
    drop_caches()
    totalmem = get_memory_line("MemTotal")
    if totalmem == -1:
        return -1
    freemem = get_memory_line("MemFree")
    if freemem == -1:
        return -1
    return totalmem - freemem

class LeakTest(stress.StressTest):
    """ Leaks testing """
    config = 'cache 0;\n'
    backend_connections = 10
    memory_leak_thresold = 32*1024 # in kib

    def assert_tempesta(self):
        """ We don't check that traffic is parsed correctly. Only detect leaks. """

    def assert_clients(self):
        """ Check only traffic size. We don't need to check responses. """
        cl_req_cnt = 0
        cl_conn_cnt = 0
        for client in self.clients:
            req, err, _ = client.results()
            cl_req_cnt += req
            cl_conn_cnt += client.connections * self.pipelined_req
        exp_min = cl_req_cnt
        exp_max = cl_req_cnt + cl_conn_cnt
        self.assertTrue(
            self.tempesta.stats.cl_msg_received >= exp_min and
            self.tempesta.stats.cl_msg_received <= exp_max,
            "Wrong cl_msg_received"
        )

    def create_servers(self):
        """ Overrirde to create needed amount of upstream servers. """
        port = tempesta.upstream_port_start_from()
        self.servers = [control.Nginx(listen_port=port)]
        for server in self.servers:
            server.config.set_ka(self.backend_connections)

    def test_kmemleak(self):
        """ Detecting leaks with kmemleak """
        if not has_kmemleak():
            return unittest.TestCase.skipTest(self, "No kmemleak")

        kml1 = read_kmemleaks()
        self.generic_test_routine(self.config)
        kml2 = read_kmemleaks()
        self.assertTrue(kml1 == kml2)

    def test_slab_memory(self):
        """ Detecting leaks with slab memory measure """
        if not has_meminfo():
            return unittest.TestCase.skipTest(self, "No meminfo")

        used1 = slab_memory()
        self.generic_test_routine(self.config)
        self.tearDown()
        used2 = slab_memory()
        tf_cfg.dbg(2, "used %i kib of slab memory=%s kib - %s kib" % (used2 - used1, used2, used1))
        self.assertTrue(used2 - used1 < self.memory_leak_thresold)

    def test_used_memory(self):
        """ Detecting leaks with total used memory measure """
        if not has_meminfo():
            return unittest.TestCase.skipTest(self, "No meminfo")

        used1 = used_memory()
        self.generic_test_routine(self.config)
        self.tearDown()
        used2 = used_memory()
        tf_cfg.dbg(2, "used %i kib of memory = %s kib - %s kib" % (used2 - used1, used2, used1))
        self.assertTrue(used2 - used1 < self.memory_leak_thresold)
