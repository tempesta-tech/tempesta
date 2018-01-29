""" Testing for long body in request """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import unittest
import body_generator

from testers import stress
from helpers import tf_cfg, control, tempesta, remote, wrk

class RequestTestBase(stress.StressTest):
    """ Test long request """
    config = "cache 0;\n"
    script = None
    wrk = None
    clients = []
    generator = None

    def create_clients_with_body(self, length):
        """ Create wrk client with long request body """
        self.generator = wrk.ScriptGenerator()
        self.generator.set_body(body_generator.generate_body(length))

        filename = self.script + ".lua"
        self.generator.make_config(filename)

        self.wrk = control.Wrk()
        self.wrk.set_script(self.script, need_copy=False)

        self.clients = [self.wrk]

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
