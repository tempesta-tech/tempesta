import re
from . import tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# Tempesta capabilities:
def servers_in_group():
    """ Max servers in server group. """
    return 32

def server_conns_default():
    """ Default connections to single upstream server. """
    return 4

def server_conns_max():
    """ Maximum connections to single upstream server. """
    return 32

def upstream_port_start_from():
    """ Start value for upstream servers listen port. Just for convinence. """
    return 8000



class Stats:
    """ Parser for TempestaFW performance statistics (/proc/tempesta/perfstat).
    """

    def __init__(self):
        self.clear()

    def clear(self):
        self.ss_pfl_hits = 0
        self.ss_pfl_misses = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.cl_msg_received = 0
        self.cl_msg_forwarded = 0
        self.cl_msg_served_from_cache = 0
        self.cl_msg_parsing_errors = 0
        self.cl_msg_filtered_out = 0
        self.cl_msg_other_errors = 0
        self.cl_conn_attempts = 0
        self.cl_established_connections = 0
        self.cl_conns_active = 0
        self.cl_rx_bytes = 0
        self.srv_msg_received = 0
        self.srv_msg_forwarded = 0
        self.srv_msg_parsing_errors = 0
        self.srv_msg_filtered_out = 0
        self.srv_msg_other_errors = 0
        self.srv_conn_attempts = 0
        self.srv_established_connections = 0
        self.srv_conns_active = 0
        self.srv_rx_bytes = 0

    def parse(self, stats):
        self.ss_pfl_hits = self.parse_option(stats, 'SS pfl hits')
        self.ss_pfl_misses = self.parse_option(stats, 'SS pfl misses')

        self.cache_hits = self.parse_option(stats, 'Cache hits')
        self.cache_misses = self.parse_option(stats, 'Cache misses')

        self.cl_msg_received = self.parse_option(
                stats, 'Client messages received')
        self.cl_msg_forwarded = self.parse_option(
                stats, 'Client messages forwarded')
        self.cl_msg_served_from_cache = self.parse_option(
                stats, 'Client messages served from cache')
        self.cl_msg_parsing_errors = self.parse_option(
                stats, 'Client messages parsing errors')
        self.cl_msg_filtered_out = self.parse_option(
                stats, 'Client messages filtered out')
        self.cl_msg_other_errors = self.parse_option(
                stats, 'Client messages other errors')
        self.cl_conn_attempts = self.parse_option(
                stats, 'Client connection attempts')
        self.cl_established_connections = self.parse_option(
                stats, 'Client established connections')
        self.cl_conns_active = self.parse_option(
                stats, 'Client connections active')
        self.cl_rx_bytes = self.parse_option(
                stats, 'Client RX bytes')

        self.srv_msg_received = self.parse_option(
                stats, 'Server messages received')
        self.srv_msg_forwarded = self.parse_option(
                stats, 'Server messages forwarded')
        self.srv_msg_parsing_errors = self.parse_option(
                stats, 'Server messages parsing errors')
        self.srv_msg_filtered_out = self.parse_option(
                stats, 'Server messages filtered out')
        self.srv_msg_other_errors = self.parse_option(
                stats, 'Server messages other errors')
        self.srv_conn_attempts = self.parse_option(
                stats, 'Server connection attempts')
        self.srv_established_connections = self.parse_option(
                stats, 'Server established connections')
        self.srv_conns_active = self.parse_option(
                stats, 'Server connections active')
        self.srv_rx_bytes = self.parse_option(
                stats, 'Server RX bytes')

    def parse_option(self, stats, name):
        s = '%s\s+: (\d+)' % name
        m = re.search(s.encode('ascii'), stats)
        if m:
            return int(m.group(1))
        return -1

#-------------------------------------------------------------------------------
# Config Helpers
#-------------------------------------------------------------------------------

class ServerGroup:

    def __init__(self, name, sched = 'round-robin'):
        self.name = name
        self.sched = sched
        self.servers = []

    def add_server(self, ip, port, conns = server_conns_default()):
        assert(conns < server_conns_max())
        assert(len(self.servers) < servers_in_group())
        conns_str = ''
        conns_str = (' conns_n=%d' % conns if (conns != server_conns_default())
                     else '')
        self.servers.append('server %s:%d%s;' % (ip, port, conns_str))

    def get_config(self):
        sg = ('srv_group %s ' % name) if (self.name != 'default') else ''
        sched_space = '=' if (self.name != 'default') else ' '
        sg += 'sched%s%s' % (sched_space, self.sched)
        if self.name != 'default':
            sg += ' {\n'
        else:
            sg += ';\n'
        ident = '\t' if self.name != 'default' else ''
        for s in self.servers:
            sg += '%s%s\n' % (ident, s)
        if self.name != 'default':
            sg += '}\n\n'
        return sg

class Config:
    """ Creates Tempesta config file. """
    def __init__(self):
        self.server_groups = []

    def add_sg(self, new_sg):
        for sg in self.server_groups:
            assert(sg.name != new_sg.name)
        self.server_groups.append(new_sg)

    def get_config(self):
        cfg = self.defconfig + '\n'
        for sg in self.server_groups:
            cfg += sg.get_config()
        return cfg

    def set_defconfig(self, config):
        self.defconfig = config
