"""
Live reconfiguration stress test for custom server group
with health monitor.
"""

from helpers import tempesta
from . import reconf_stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class HealthMonitorCustomSg(reconf_stress.LiveReconfStress):

    sg_name = 'custom'
    hmonitor = 'monitor1'
    defconfig = (
        'server_failover_http 404 500 30;\n'
        'health_check monitor1 {\n'
        '  request "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";\n'
        '  request_url "/page.html";\n'
        '  resp_code 200;\n'
        '  timeout 15;\n'
        '}\n'
        'sched_http_rules {\n'
        '  match custom * * *;\n'
        '}\n'
        '\n')

    def add_sg(self, config, sg_name, servers):
        sg = tempesta.ServerGroup(sg_name)
        for s in servers:
            sg.add_server(s.ip, s.config.port, s.conns_n)
        sg.options = ' health %s;' % self.hmonitor
        config.add_sg(sg)

    def test_hm_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_add)

    def test_hm_del_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del)

    def test_hm_del_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del_add)


class HealthMonitorChangedAutoCustomSg(HealthMonitorCustomSg):

    hmonitor_new = 'auto'

    def set_hmonitor(self, hm):
        for sg in self.tempesta.config.server_groups:
            sg.options = ' health %s;' % hm

    def configure_srvs_add(self):
        reconf_stress.LiveReconfStress.configure_srvs_add(self)
        self.set_hmonitor(self.hmonitor_new)

    def configure_srvs_del(self):
        reconf_stress.LiveReconfStress.configure_srvs_del(self)
        self.set_hmonitor(self.hmonitor_new)

    def configure_srvs_del_add(self):
        reconf_stress.LiveReconfStress.configure_srvs_del_add(self)
        self.set_hmonitor(self.hmonitor_new)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
