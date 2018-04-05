__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from . import remote

def configure_tcp():
    """ Configuring TCP for faster reuse the same TCP ports.
    A lot of sockets are created in tests and bound to specific ports.
    Release them quicker to reuse the ports in the next test case. """

    for node in [remote.server, remote.tempesta, remote.client]:
        node.run_cmd("sysctl -w net.ipv4.tcp_tw_recycle=1")
        node.run_cmd("sysctl -w net.ipv4.tcp_tw_reuse=1")
        node.run_cmd("sysctl -w net.ipv4.tcp_fin_timeout=10")

def configure():
    """ Prepare nodes before running tests """

    configure_tcp()
