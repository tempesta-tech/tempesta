"""Helpers for flacky network testing. """

from __future__ import print_function

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def get_sock_count(node, server, state=None):
    """Get count of sockets connected to given peer"""
    ss_filter = ('state %s' % state) if state else ''
    # Count only if  destination peer matches
    cmd = 'ss -H -t %s "dst %s" | wc -l' % (ss_filter, server)
    stdout, _ = node.run_cmd(cmd)
    return int(stdout)

def get_sock_estab_count(node, server):
    """Get count of sockets in state TCP_ESTAB connected to given peer"""
    return get_sock_count(node, server, 'established')

class Filter(object):
    """Control iptables on target node (Client, Server or Tempesta)."""

    directions = ['INPUT', 'OUTPUT', 'FORWARD']

    def __init__(self, node, direction=None):
        self.node = node
        self.direction = direction if direction else self.directions[0]
        self.chain = ''.join(['TempestaTestChain', self.node.type,
                              self.direction])

    def init_chains(self):
        """Create custom chain and insert before every other chain or rule."""
        create_cmd = 'iptables -N %s' % self.chain
        self.node.run_cmd(create_cmd)
        insert_cmd = 'iptables -I %s -j %s' % (self.direction, self.chain)
        self.node.run_cmd(insert_cmd)

    def drop_on_ports(self, dest_ports):
        """Block given list of ports."""
        for port in dest_ports:
            drop_cmd = ('iptables -A %s -p tcp --dport %d -j DROP'
                        % (self.chain, port))
            self.node.run_cmd(drop_cmd)

    def clean(self):
        """Remove all rules from custom chain."""
        clean_cmd = 'iptables -F %s' % self.chain
        self.node.run_cmd(clean_cmd)

    def clean_up(self):
        """Full cleanup: completely remove custom rule."""
        self.clean()
        remove_links_cmd = ('iptables -D %s -j %s'
                            % (self.direction, self.chain))
        self.node.run_cmd(remove_links_cmd)
        remove_chain_cmd = 'iptables -X %s' % self.chain
        self.node.run_cmd(remove_chain_cmd)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
