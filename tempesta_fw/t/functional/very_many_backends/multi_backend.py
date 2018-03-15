""" Test template """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import socket
import struct
import os
import re
import uuid

from testers import stress
from helpers import tf_cfg, control, tempesta, remote, stateful, nginx, error


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

class Listener(object):
    """ Server listner info """
    port = 80
    ip_listen = "0.0.0.0"
    location = ""
    config = ""
    config_have_status = """
    location /nginx_status {
            stub_status on;
        }
"""
    config_server_template = """
    server {
        listen        %s;

        location / {
            root %s;
        }
        %s
    }
"""
    def __init__(self, ip_listen, port, location,
                 backlog=None, has_status=False):
        if backlog is None:
            listen_str = "%s:%i" % (ip_listen, port)
        else:
            listen_str = "%s:%i backlog=%s" % (ip_listen, port, backlog)
        self.ip_listen = ip_listen
        self.port = port
        self.location = location
        if has_status:
            self.config = self.config_server_template % \
                (listen_str, location, self.config_have_status)
        else:
            self.config = self.config_server_template % \
                (listen_str, location, "")

class ConfigMultiplePorts(object):
    """ Nginx config file builder. """

    config_name = ""
    uuid = ""
    multi_accept = "off"
    keepalive_timeout = 65
    keepalive_requests = 100
    pidfile_name = ""
    worker_processes = 'auto'
    worker_rlimit_nofile = 1024
    worker_connections = 1024
    workdir = '/'
    config = ''
    location = "/var/www/html"
    main_template = """
pid %s;
worker_processes %s;
worker_rlimit_nofile %s;
"""
    events_template = """
events {
    multi_accept %s;
    worker_connections %i;
    use epoll;
}
"""

    http_options_template = """
    keepalive_timeout %i;
    keepalive_requests %i;
"""

    http_options_static = """
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;
"""

    def __init__(self, workdir, workers):
        self.uuid = str(uuid.uuid1())
        self.listeners = []
        self.set_workdir(workdir)
        self.set_workers(workers)
        self.set_resourse_location()
        self.config_name = "nginx-%s.conf" % self.uuid
        self.pidfile_name = '/var/run/nginx-%s.pid' % self.uuid

    def build_config(self):
        """ Building config file """
        pidfile = os.path.join(self.workdir, self.pidfile_name)
        cfg_main = self.main_template % (pidfile,
                     self.worker_processes, self.worker_rlimit_nofile)
        cfg_events = self.events_template % \
             (self.multi_accept, self.worker_connections)

        http_options = self.http_options_template % \
            (self.keepalive_timeout, self.keepalive_requests)

        cfg_http = "http {" + http_options + self.http_options_static

        for server in self.listeners:
            cfg_http = cfg_http + server.config

        cfg_http = cfg_http + "}\n"
        self.config = cfg_main + cfg_events + cfg_http

    def add_server(self, ip_listen, port):
        """ Add new server listener """
        if len(self.listeners) == 0:
            listener = Listener(ip_listen, port, self.location, has_status=True)
        else:
            listener = Listener(ip_listen, port, self.location)
        self.listeners.append(listener)
        self.build_config()

    def __replace(self, exp, value):
        regex = re.compile(exp)
        self.config = regex.sub(value, self.config)

    def enable_multi_accept(self):
        self.multi_accept = "on"
        self.build_config()

    def set_worker_connections(self, wk):
        self.worker_connections = wk
        self.build_config()

    def set_ka(self, req=100, timeout=65):
        """ Set Keepalive parameters for server. """
        self.keepalive_requests = req
        self.keepalive_timeout = timeout
        self.build_config()

    def set_workers(self, workers='auto'):
        if workers == 'auto':
            self.worker_processes = 'auto'
            self.build_config()
            return
        max_workers = int(tf_cfg.cfg.get('Server', 'max_workers'))
        if max_workers <= 0:
            self.worker_processes = workers
            self.build_config()
            return
        nw = int(workers)
        if nw > max_workers:
            tf_cfg.dbg(1, 'Too much (%i) workers requested. ' \
                    'Only %i is possible' % (nw, max_workers))
            nw = max_workers
        self.worker_processes = str(nw)
        self.build_config()

    def set_worker_rlimit_nofile(self, rlimit='auto'):
        self.worker_rlimit_nofile = rlimit
        self.build_config()

    def set_workdir(self, workdir):
        error.assertTrue(workdir)
        self.workdir = workdir
        self.build_config()

    def set_resourse_location(self, location=''):
        if not location:
            location = tf_cfg.cfg.get('Server', 'resources')
        self.location = location
        self.build_config()


class NginxMP(control.Nginx):
    first_port = 0
    config = None

    def __init__(self, listen_port, workers=1, ports_n=1, listen_ip=None):
        # We don't call costructor of control.Nginx
        self.first_port = listen_port
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get('Server', 'workdir')

        if listen_ip is None:
            self.ip = tf_cfg.cfg.get('Server', 'ip')
        else:
            self.ip = listen_ip

        self.config = ConfigMultiplePorts(self.workdir, workers)
        for i in range(ports_n):
            self.config.add_server(self.ip, listen_port + i)

        self.clear_stats()
        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()
        self.err_msg = "Can't %s Nginx on %s"
        self.active_conns = 0
        self.requests = 0
        self.stop_procedures = [self.stop_nginx, self.remove_config]

    def get_name(self):
        return ':'.join([self.ip, str(self.first_port)])

    def get_stats(self):
        """ Nginx doesn't have counters for every virtual host. Spawn separate
        instances instead
        """
        self.stats_ask_times += 1
        # In default tests configuration Nginx status available on
        # `nginx_status` page.
        uri = 'http://%s:%d/nginx_status' % (self.node.host, self.first_port)
        cmd = 'curl %s' % uri
        out, _ = remote.client.run_cmd(
            cmd, err_msg=(self.err_msg % ('get stats of', self.get_name())))
        m = re.search(r'Active connections: (\d+) \n'
                      r'server accepts handled requests\n \d+ \d+ (\d+)',
                      out)
        if m:
            # Current request increments active connections for nginx.
            self.active_conns = int(m.group(1)) - 1
            # Get rid of stats requests influence to statistics.
            self.requests = int(m.group(2)) - self.stats_ask_times

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
            server = NginxMP(listen_port=self.base_port,
                           ports_n=self.num_listeners_per_interface,
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
        has_base_excpt = False
        try:
            super(MultipleBackends, self).tearDown()
        except Exception as exc:
            has_base_excpt = True
            excpt = exc
        tf_cfg.dbg(2, "Removing interfaces")
        remove_interfaces(self.interface, self.ips)
        self.ips = []
        if has_base_excpt:
            raise excpt

    def test(self):
        """ Test 1M backends """
        self.generic_test_routine(self.config)
