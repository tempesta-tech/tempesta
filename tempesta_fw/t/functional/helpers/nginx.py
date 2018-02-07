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
    config_server_template = """
    server {
        listen        %s:%i;

        location / {
            root %s;
        }
        location /nginx_status {
            stub_status on;
        }
    }
"""
    def __init__(self, ip_listen, port, location):
        self.ip_listen = ip_listen
        self.port = port
        self.location = location
        self.config = self.config_server_template % (ip_listen, port, location)

class Config(object):
    """ Nginx config file builder. """

    config_name = ""
    uuid = ""
    keepalive_timeout = 65
    keepalive_requests = 100
    pidfile_name = ""
    worker_processes = 'auto'
    worker_connections = 1024
    workdir = '/'
    config = ''
    location = "/var/www/html"
    config_main_template = """
pid %s;
worker_processes %s;
"""
    config_events_template = """
events {
    worker_connections %i;
    use epoll;
}
"""

    config_http_options_template = """
    keepalive_timeout %i;
    keepalive_requests %i;
"""

    config_http_options_static = """
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
        config_main = self.config_main_template % (os.path.join(self.workdir, self.pidfile_name), self.worker_processes)
        config_events = self.config_events_template % (self.worker_connections)
        config_http_options = self.config_http_options_template % (self.keepalive_timeout, self.keepalive_requests)
        config_http = "http {" + config_http_options + self.config_http_options_static

        for server in self.listeners:
            config_http = config_http + server.config

        config_http = config_http + "}\n"
        self.config = config_main + config_events + config_http

    def add_server(self, ip_listen, port):
        """ Add new server listener """
        listener = Listener(ip_listen, port, self.location)
        self.listeners.append(listener)
        self.build_config()

    def __replace(self, exp, value):
        regex = re.compile(exp)
        self.config = regex.sub(value, self.config)

    def set_ka(self, req, timeout=65):
        """ Set Keepalive parameters for server. """
        self.keepalive_requests = req
        self.keepalive_timeout = timeout
        self.build_config()

    def set_workers(self, workers='auto'):
        self.worker_processes = workers
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
