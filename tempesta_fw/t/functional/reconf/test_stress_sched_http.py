"""
Live reconfiguration stress test for http scheduler.
"""

from helpers import tempesta
from . import reconf_stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class SchedHttp(reconf_stress.LiveReconfStress):

    orig_sg = 'origin'
    alt_sg = 'alternate'

    def configure_http_sched(self, active_group):
        defconfig = (
        'sched_http_rules {\n'
        '  match %s * * *;\n'
        '}\n'
        '\n' % active_group)
        config = self.make_config(self.orig_sg, self.const_srvs, defconfig)
        self.add_sg(config, self.alt_sg, self.add_srvs)
        self.tempesta.config = config

    def configure_start(self):
        self.configure_http_sched(self.orig_sg)

    def configure_reconfig(self):
        self.configure_http_sched(self.alt_sg)

    def test_hash_add_srvs(self):
        self.stress_reconfig_generic(self.configure_start,
                                     self.configure_reconfig)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
