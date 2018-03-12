"""
TLS Stress tests.
"""

import os
from helpers import control, tf_cfg
from testers import stress

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class StressTls(stress.StressTest):
    """Load Tempesta with multiple TLS connections.
    """

    defconfig = ("ssl_certificate %s/tfw-root.crt;\n"
                 "ssl_certificate_key %s/tfw-root.key;\n"
                 "listen 443 proto=https;\n\n")

    def create_clients(self):
        wrk = control.Wrk(ssl=True)
        # Wrk can't handle very big amound of TLS connections
        wrk.connections = min(
            int(tf_cfg.cfg.get('General', 'concurrent_connections')),
            100)
        self.clients = [wrk]

    def test_tls(self):
        path = os.path.dirname(self.tempesta.config_name)
        dir = os.path.dirname(__file__)
        cert = "%s/tfw-root.crt"
        key = "%s/tfw-root.key"
        self.tempesta.node.copy_file_to_node(cert % dir, cert % path)
        self.tempesta.node.copy_file_to_node(key % dir, key % path)
        config = self.defconfig % (path, path)
        self.generic_test_routine(config)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
