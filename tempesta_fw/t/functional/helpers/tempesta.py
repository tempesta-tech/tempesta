import re
import os
from . import error

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

# Tempesta capabilities:
def servers_in_group():
    """ Max servers in server group. """
    return 32

def server_conns_default():
    """ Default connections to single upstream server. """
    return 32

def server_conns_max():
    """ Maximum connections to single upstream server. """
    return 32

def upstream_port_start_from():
    """ Start value for upstream servers listen port. Just for convenience. """
    return 8000

# Version_info_cache
tfw_version = ''

def version():
    """TempestaFW current version. Defined in tempesta_fw.h:
    #define TFW_VERSION		"0.5.0-pre6"
    """
    global tfw_version
    if tfw_version:
        return tfw_version
    version_header = ''.join([os.path.dirname(os.path.realpath(__file__)),
                              '/../../../tempesta_fw.h'])
    with open(version_header, 'r') as header:
        read_data = header.read()
        m = re.search(r'#define TFW_VERSION\s+"([0-9a-z.-]+)"', read_data)
        error.assertTrue(m)
        tfw_version = m.group(1)
        return tfw_version
    error.bug()


class Stats(object):
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

    @staticmethod
    def parse_option(stats, name):
        s = r'%s\s+: (\d+)' % name
        m = re.search(s.encode('ascii'), stats)
        if m:
            return int(m.group(1))
        return -1

#-------------------------------------------------------------------------------
# Config Helpers
#-------------------------------------------------------------------------------

class ServerGroup(object):

    def __init__(self, name='default', sched='ratio'):
        self.name = name
        self.sched = sched
        self.servers = []
        # Server group options, inserted after servers.
        self.options = ''

    def add_server(self, ip, port, conns=server_conns_default()):
        error.assertTrue(conns <= server_conns_max())
        error.assertTrue(len(self.servers) < servers_in_group())
        conns_str = (' conns_n=%d' % conns if (conns != server_conns_default())
                     else '')
        self.servers.append('server %s:%d%s;' % (ip, port, conns_str))

    def get_config(self):
        sg = ''
        if self.name == 'default':
            sg = '\n'.join(['sched %s;' % self.sched] + self.servers
                           + [self.options])
        else:
            sg = '\n'.join(
                ['srv_group %s {' % self.name] + ['sched %s;' % self.sched] +
                self.servers + [self.options] + ['}'])
        return sg

class Config(object):
    """ Creates Tempesta config file. """
    def __init__(self):
        self.server_groups = []
        self.defconfig = ''

    def add_sg(self, new_sg):
        for sg in self.server_groups:
            error.assertTrue(sg.name != new_sg.name)
        self.server_groups.append(new_sg)

    def get_config(self):
        cfg = '\n'.join([sg.get_config() for sg in self.server_groups] +
                        [self.defconfig])
        return cfg

    def set_defconfig(self, config):
        self.defconfig = config
