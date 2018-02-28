"""
Live reconfiguration stress test for custom server group
with health monitor.
"""

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

    def test_hm_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_add)

    def test_hm_del_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del)

    def test_hm_del_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del_add)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
