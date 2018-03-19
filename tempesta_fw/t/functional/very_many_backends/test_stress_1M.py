
__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import very_many_backends.multi_backend

from helpers import tf_cfg, tempesta

class ManyBackends1InGroup(very_many_backends.multi_backend.MultipleBackends):
    """ 1 backend in server group """
    num_interfaces = 8
    num_listeners_per_interface = 128
    def configure_tempesta(self):
        """ Configure tempesta 1 port in group """
        sgid = 0
        for server in self.servers:
            for listener in server.config.listeners:
                server_group = tempesta.ServerGroup('default-%i' % sgid)
                server_group.add_server(server.ip, listener.port,
                                        server.conns_n)
                self.tempesta.config.add_sg(server_group)
                sgid = sgid + 1

    def test(self):
        self.generic_test_routine(self.config)

class ManyBackends32InGroup(very_many_backends.multi_backend.MultipleBackends):
    """ 32 backends in server group """
    num_interfaces = 8
    num_listeners_per_interface = 64
    def configure_tempesta(self):
        """ Configure tempesta 32 port in group """
        sgid = 0
        group_servers = []
        for server in self.servers:
            for listener in server.config.listeners:
                group_servers.append((server, listener))
                if len(group_servers) == 32:
                    server_group = tempesta.ServerGroup('default-%i' % sgid)
                    for (srv, lstn) in group_servers:
                        server_group.add_server(srv.ip, lstn.port, srv.conns_n)
                    self.tempesta.config.add_sg(server_group)
                    sgid = sgid + 1
                    group_servers = []

    def test(self):
        self.generic_test_routine(self.config)
