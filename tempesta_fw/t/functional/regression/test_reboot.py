"""
Test TempestaFW reeboot under heavy load.
"""

from __future__ import print_function
import unittest
import threading
from helpers import deproxy, tf_cfg, tempesta, remote, control
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class RebootTest(stress.StressTest):
    """Start load only when TempestaFW is up"""

    restart_cycles = 10

    # Override test duration. Mostly there is no sence to load TempestaFW for a
    # long time before rebooting it.
    duration = 1

    def create_clients(self):
        self.wrk = control.Wrk()
        self.wrk.duration = self.duration + 1
        self.clients = [self.wrk]

    def reboot_routine(self, config):
        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(config)
        self.configure_tempesta()
        control.servers_start(self.servers)
        self.wrk.prepare()

        for i in range(self.restart_cycles):
            self.tempesta.start()
            threading.Timer(self.duration, self.tempesta.stop).start ()
            control.client_run_blocking(self.wrk)
            # Run random command on remote node to see if it is still alive.
            remote.tempesta.run_cmd('uname')
            self.show_performance()

    def test_proxy(self):
        config = 'cache 0;\n'
        self.reboot_routine(config)

    def test_cache(self):
        config = 'cache 2;\n'
        self.reboot_routine(config)


class ContigiousRebootTest(RebootTest):
    """Reboot under constant load"""

    duration = 10

    def reboot(self):
        while self.in_progress:
            self.tempesta.stop()
            # Run random command on remote node to see if it is still alive.
            remote.tempesta.run_cmd('uname')
            self.tempesta.start()

    def reboot_routine(self, config):
        # Set defconfig for Tempesta.
        self.tempesta.config.set_defconfig(config)
        self.configure_tempesta()
        control.servers_start(self.servers)
        self.tempesta.start()

        self.wrk.prepare()
        self.in_progress = True
        threading.Timer(1, self.reboot).start ()

        control.client_run_blocking(self.wrk)
        self.in_progress = False
        self.show_performance()

    def tear_down(self):
        self.in_progress = False
        RebootTest.tear_down()
