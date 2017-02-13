""" Nginx helpers. """

import re
from . import tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Config:
    """ Nginx config file builder. """

    def __init__(self, workdir, port, workers):
        self.port = 80 # keep port linked with default config
        self.config = """
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
            root /srv/http;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
        """
        self.set_port(port)
        self.set_workdir(workdir)
        self.set_workers(workers)
        self.set_resourse_location()

    def set_ka(self, req, timeout=65):
        """ Set Keepalive parameters for server. """
        r = re.compile('keepalive_timeout[ ]+(\d+);')
        self.config = r.sub('keepalive_timeout ' + str(timeout) + ';', self.config)
        r = re.compile('keepalive_requests[ ]+(\d+);')
        self.config = r.sub('keepalive_requests ' + str(req) + ';', self.config)

    def set_workers(self, workers='auto'):
        r = re.compile('worker_processes[ ]+(\w+);')
        self.config = r.sub('worker_processes ' + str(workers) + ';', self.config)

    def set_port(self, port):
        self.port = int(port)
        self.config_name = 'nginx_%d.conf' % port
        self.pidfile_name = 'nginx_%d.pid' % port
        r = re.compile('listen[ ]+(\w+);')
        self.config = r.sub('listen ' + str(port) + ';', self.config)

    def set_workdir(self, dir):
        assert(len(dir))
        if not dir.endswith('/'):
            dir = dir + '/'
        pid = dir + self.pidfile_name
        root = dir + 'http'
        r = re.compile('pid[ ]+([\w._/]+);')
        self.config = r.sub('pid ' + pid + ';', self.config)

    def set_resourse_location(self, location=''):
        if not location:
            location = tf_cfg.cfg.get('Server', 'resources')
        r = re.compile('root[ ]+([\w._/]+);')
        self.config = r.sub('root ' + location + ';', self.config)
