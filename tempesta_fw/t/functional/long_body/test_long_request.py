""" Testing for long body in request """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import unittest
import body_generator
import os

from testers import stress
from helpers import tf_cfg, control, tempesta, remote, wrk

class RequestTestBase(stress.StressTest):
    """ Test long request """
    config = "cache 0;\n"
    root = "/tmp/long_body/"
    script = None
    scriptdir = root + "scripts/"
    wrk = None
    clients = []
    generator = None

    def create_clients_with_body(self, length):
        """ Create wrk client with long request body """
        self.generator = wrk.ScriptGenerator()
        self.generator.set_body(body_generator.generate_body(length))
        if not os.path.exists(self.root):
            os.mkdir(self.root)
        elif not os.path.isdir(self.root):
            raise Exception("%s already exists" % self.root)

        if not os.path.exists(self.scriptdir):
            os.mkdir(self.scriptdir)
        elif not os.path.isdir(self.scriptdir):
            raise Exception("%s already exists" % self.scriptdir)

        self.generator.make_config(self.scriptdir + self.script + ".lua")
        self.wrk = control.Wrk()
        self.wrk.set_script(self.script, self.scriptdir)
        self.clients = [self.wrk]

    def tearDown(self):
        super(RequestTestBase, self).tearDown()
        self.generator.remove_config()
        os.rmdir(self.scriptdir)

class RequestTest1k(RequestTestBase):
    """ Test long request """
    script = "request_1k"

    def create_clients(self):
        self.create_clients_with_body(1024)

    def test(self):
        """ Test for 1kbyte body """
        self.generic_test_routine(self.config)

class RequestTest1M(RequestTestBase):
    """ Test long request """
    script = "request_1M"

    def create_clients(self):
        self.create_clients_with_body(1024**2)

    def test(self):
        """ Test for 1Mbyte body """
        self.generic_test_routine(self.config)
