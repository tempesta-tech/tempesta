"""
Live reconfiguration stress test for ratio scheduler.
"""

from helpers import tempesta
from . import reconf_stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# Ratio Static tests

class SchedRatioStaticImplDefaultSg(reconf_stress.LiveReconfStress):

    sg_name = 'default'
    sched = 'ratio static'

    def set_ratio_sched(self):
        for sg in self.tempesta.config.server_groups:
            sg.sched = self.sched

    def configure_srvs_start(self):
        reconf_stress.LiveReconfStress.configure_srvs_start(self)
        self.set_ratio_sched()

    def configure_srvs_add(self):
        reconf_stress.LiveReconfStress.configure_srvs_add(self)
        self.set_ratio_sched()

    def configure_srvs_del(self):
        reconf_stress.LiveReconfStress.configure_srvs_del(self)
        self.set_ratio_sched()

    def configure_srvs_del_add(self):
        reconf_stress.LiveReconfStress.configure_srvs_del_add(self)
        self.set_ratio_sched()

    def test_ratio_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_add)

    def test_ratio_del_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del)

    def test_ratio_del_add_srvs(self):
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del_add)


class SchedRatioStaticExplDefaultSg(SchedRatioStaticImplDefaultSg):

    def set_ratio_sched(self):
        for sg in self.tempesta.config.server_groups:
            sg.sched = self.sched
            sg.implicit = False

class SchedRatioStaticCustomSg(SchedRatioStaticImplDefaultSg):

    sg_name = 'custom'
    defconfig = (
        'sched_http_rules {\n'
        '  match custom * * *;\n'
        '}\n'
        '\n')

# Ratio Dynamic tests

class SchedRatioDynamicImplDefaultSg(SchedRatioStaticImplDefaultSg):

    sched = 'ratio dynamic'

class SchedRatioDynamicExplDefaultSg(SchedRatioStaticExplDefaultSg):

    sched = 'ratio dynamic'

class SchedRatioDynamicCustomSg(SchedRatioStaticCustomSg):

    sched = 'ratio dynamic'

# Ratio Predict tests

class SchedRatioPredictImplDefaultSg(SchedRatioStaticImplDefaultSg):

    sched = 'ratio predict'

class SchedRatioPredictExplDefaultSg(SchedRatioStaticExplDefaultSg):

    sched = 'ratio predict'

class SchedRatioPredictCustomSg(SchedRatioStaticCustomSg):

    sched = 'ratio predict'

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
