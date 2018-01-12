"""
Live reconfiguration stress test for grace shutdown.
"""

from helpers import control, tf_cfg
from . import reconf_stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class SchedStickyGraceRatioSched(reconf_stress.LiveReconfStress):

    sg_name = 'default'
    sched = 'ratio static'
    defconfig = (
        'cache 0;\n'
        'sticky enforce;\n'
        'sticky_secret "f00)9eR59*_/22";\n'
        'grace_shutdown_time %d;\n'
        '\n' % int(tf_cfg.cfg.get('General', 'Duration')))
    clients_num = min(int(tf_cfg.cfg.get('General', 'concurrent_connections')),
                      1000)

    def create_clients(self):
        # See test_sticky_sess_stress
        self.wrk = control.Wrk(threads=self.clients_num)
        self.wrk.connections = self.wrk.threads
        self.wrk.set_script("cookie-many-clients")
        self.clients = [self.wrk]

    def set_ratio_sched(self):
        for sg in self.tempesta.config.server_groups:
            sg.sched = self.sched
            sg.options = 'sticky_sessions;'

    def configure_srvs_start(self):
        reconf_stress.LiveReconfStress.configure_srvs_start(self)
        self.set_ratio_sched()

    def configure_srvs_del(self):
        config = self.make_config(self.sg_name, [])
        self.tempesta.config = config
        self.set_ratio_sched()

    def test_ratio_del_srvs(self):
        '''All servers are removed from configuration, but a relatively long
        grace shutdown period is set, since no new sessions are established
        test client should recieve just aa bit of errors.'''
        self.stress_reconfig_generic(self.configure_srvs_start,
                                     self.configure_srvs_del)

class SchedStickyGraceHashSched(SchedStickyGraceRatioSched):

    sched = 'hash'

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
