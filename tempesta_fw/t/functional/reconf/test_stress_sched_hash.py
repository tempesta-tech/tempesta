"""
Live reconfiguration stress test for hash scheduler.
"""

from helpers import tempesta
from . import reconf_stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class SchedHashImplDefaultSg(reconf_stress.LiveReconfStress):

    sg_name = 'default'

    def set_hash_sched(self):
        for sg in self.tempesta.config.server_groups:
            sg.sched = 'hash'

    def configure_srvs_start(self):
        reconf_stress.LiveReconfStress.configure_srvs_start(self)
        self.set_hash_sched()

    def configure_srvs_add(self):
        reconf_stress.LiveReconfStress.configure_srvs_add(self)
        self.set_hash_sched()

    def configure_srvs_del(self):
        reconf_stress.LiveReconfStress.configure_srvs_del(self)
        self.set_hash_sched()

    def configure_srvs_del_add(self):
        reconf_stress.LiveReconfStress.configure_srvs_del_add(self)
        self.set_hash_sched()

    def test_hash_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_add)

    def test_hash_del_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del)

    def test_hash_del_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del_add)


class SchedHashExplDefaultSg(SchedHashImplDefaultSg):

    def set_hash_sched(self):
        for sg in self.tempesta.config.server_groups:
            sg.sched = 'hash'
            sg.implicit = False

class SchedHashCustomSg(SchedHashImplDefaultSg):

    sg_name = 'custom'
    defconfig = (
        'sched_http_rules {\n'
        '  match custom * * *;\n'
        '}\n'
        '\n')

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
