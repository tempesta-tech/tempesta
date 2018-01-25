""" Testing for long body in response """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import os
import body_generator

from testers import stress
from helpers import tf_cfg, control, tempesta, remote

class ResponseTestBase(stress.StressTest):
    """ Test long response """
    config = "cache 0;\n"
    root = "/tmp/long_body/"
    wwwdir = root + "www/"
    uri = "/long.bin"
    filename = wwwdir + uri

    def create_content(self, length):
        """ Create content file """
        if not os.path.exists(self.root):
            os.mkdir(self.root)
        elif not os.path.isdir(self.root):
            raise Exception("%s already exists" % self.root)

        if not os.path.exists(self.wwwdir):
            os.mkdir(self.wwwdir)
        elif not os.path.isdir(self.wwwdir):
            raise Exception("%s already exists" % self.wwwdir)

        bfile = open(self.filename, 'w')
        bfile.write(body_generator.generate_body(length))
        bfile.close()

    def remove_content(self):
        """ Remove content file """
        os.unlink(self.filename)
        os.rmdir(self.wwwdir)

    def tearDown(self):
        super(ResponseTestBase, self).tearDown()
        self.remove_content()

    def create_clients(self):
        """ Create wrk with specified uri """
        self.clients = [control.Wrk(uri=self.uri)]

    def create_servers_with_body(self, length):
        """ Create nginx server with long response body """
        self.create_content(length)
        port = tempesta.upstream_port_start_from()
        nginx = control.Nginx(listen_port=port)
        nginx.config.set_resourse_location(self.wwwdir)
        self.servers = [nginx]

class ResponseTest1k(ResponseTestBase):
    """ 1k test """
    def create_servers(self):
        self.create_servers_with_body(1024)

    def test(self):
        """ Test for 1kbyte body """
        self.generic_test_routine(self.config)

class ResponseTest1M(ResponseTestBase):
    """ 1M test """
    def create_servers(self):
        self.create_servers_with_body(1024**2)

    def test(self):
        """ Test for 1Mbyte body """
        self.generic_test_routine(self.config)
