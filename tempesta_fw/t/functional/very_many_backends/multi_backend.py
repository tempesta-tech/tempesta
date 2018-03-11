""" Test template """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import socket
import struct

from testers import stress
from helpers import tf_cfg, control, tempesta, remote


def ip_str_to_number(ip_addr):
    """ Convert ip to number """
    packed = socket.inet_aton(ip_addr)
    return struct.unpack("!L", packed)[0]

def ip_number_to_str(ip_addr):
    """ Convert ip in numeric form to string """
    packed = struct.pack("!L", ip_addr)
    return socket.inet_ntoa(packed)

def create_interface(iface_id, base_iface_name, base_ip):
    """ Create interface alias for listeners on nginx machine """
    base_ip_addr = ip_str_to_number(base_ip)
    iface_ip_addr = base_ip_addr + iface_id
    iface_ip = ip_number_to_str(iface_ip_addr)

    iface = "%s:%i" % (base_iface_name, iface_id)

    command = "LANG=C ip address add %s/24 dev %s label %s" % \
        (iface_ip, base_iface_name, iface)
    remote.server.run_cmd(command)
    return (iface, iface_ip)

def remove_interface(interface_name, iface_ip):
    """ Remove interface """
    template = "LANG=C ip address del %s/24 dev %s"
    try:
        tf_cfg.dbg(3, "Removing ip %s" % iface_ip)
        remote.server.run_cmd(template % (iface_ip, interface_name))
    except:
        tf_cfg.dbg(3, "Interface alias already removed")

def create_interfaces(base_interface_name,  base_interface_ip, number_of_ip):
    """ Create specified amount of interface aliases """
    ips = []
    for i in range(number_of_ip):
        (_, ip) = create_interface(i, base_interface_name, base_interface_ip)
        ips.append(ip)
    return ips

def remove_interfaces(base_interface_name, ips):
    """ Remove previously created interfaces """
    for ip in ips:
        remove_interface(base_interface_name, ip)

class MultipleBackends(stress.StressTest):
    """ Testing for 1M backends """
    num_interfaces = 1
    num_listeners_per_interface = 1

    interface = None
    base_ip = None
    ips = []
    config = 'cache 0;\n'

    base_port = 16384

    def create_servers(self):
        self.interface = tf_cfg.cfg.get('Server', 'aliases_interface')
        self.base_ip = tf_cfg.cfg.get('Server',   'aliases_base_ip')
        self.ips = create_interfaces(self.interface, self.base_ip,
                                     self.num_interfaces)
        for ip in self.ips:
            server = control.Nginx(listen_port=self.base_port, \
                                ports_n=self.num_listeners_per_interface, \
                                listen_ip=ip)
            self.servers.append(server)

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

    def tearDown(self):
        """ Stop nginx and tempesta, clear interfaces after this """
        super(MultipleBackends, self).tearDown()
        tf_cfg.dbg(2, "Removing interfaces")
        remove_interfaces(self.interface, self.ips)
        self.ips = []

    def test(self):
        """ Test 1M backends """
        self.generic_test_routine(self.config)
