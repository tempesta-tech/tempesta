""" Nginx helpers. """

from __future__ import print_function
import uuid
import re
import os
from . import tf_cfg, error

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

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

class Config(object):
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

    listeners = None

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

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
