""" Nginx helpers. """

from __future__ import print_function
import re
import os
from . import tf_cfg, error

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Config(object):
    """ Nginx config file builder. """

    def __init__(self, workdir, port, workers):
        self.port = 80 # keep port linked with default config
        self.config_template = """
pid /var/run/nginx.pid;
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout 65;
    keepalive_requests 100;
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

    server {
        listen        80;

        location / {
            %s;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
        """
        location = "root /srv/http"
        self.config = self.config_template % location
        self.set_port(port)
        self.set_workdir(workdir)
        self.set_workers(workers)
        self.set_resourse_location()

    def __replace(self, exp, value):
        regex = re.compile(exp)
        self.config_template = regex.sub(value, self.config_template)

    def set_ka(self, req, timeout=65):
        """ Set Keepalive parameters for server. """
        self.__replace(r'keepalive_timeout[ ]+(\d+);',
                       ' '.join(['keepalive_timeout', str(timeout), ';']))
        self.__replace(r'keepalive_requests[ ]+(\d+);',
                       ' '.join(['keepalive_requests', str(req), ';']))

    def set_workers(self, workers='auto'):
        self.__replace(r'worker_processes[ ]+(\w+);',
                       ' '.join(['worker_processes', str(workers), ';']))

    def set_port(self, port):
        self.port = int(port)
        self.config_name = 'nginx_%d.conf' % port
        self.pidfile_name = 'nginx_%d.pid' % port
        self.__replace(r'listen[ ]+(\w+);',
                       ' '.join(['listen', str(port), ';']))

    def set_workdir(self, workdir):
        error.assertTrue(workdir)
        self.__replace(r'pid[ ]+([\w._/]+);',
                       ''.join(['pid ', os.path.join(workdir, self.pidfile_name), ' ;']))

    def set_resourse_location(self, location=''):
        if not location:
            location = tf_cfg.cfg.get('Server', 'resources')
        location = "root %s" % location
        self.config = self.config_template % location

    def set_return_code(self, code=200):
        location = "return %i" % code
        self.config = self.config_template % location

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
