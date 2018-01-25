""" Wrk script generator """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

import os

class ScriptGenerator(object):
    """ Generate lua script """
    request_type = "GET"
    uri = "/"
    headers = []
    body = ""
    filename = None
    def __luaencode(self, value):
        return value

    def set_request_type(self, request_type):
        self.request_type = request_type

    def set_uri(self, uri):
        self.uri = uri

    def add_header(self, header_name, header_value):
        self.headers.append((header_name, header_value))

    def set_body(self, body):
        self.body = body

    def make_config(self, filename):
        """ Generate config and write it to file """
        self.filename = filename
        config = open(filename, 'w')
        config.write("local r = {\n")
        config.write("    method = \"%s\",\n" % self.__luaencode(self.request_type))
        config.write("    path = \"%s\",\n" % self.__luaencode(self.uri))
        config.write("    headers = {\n")
        for header in self.headers:
            config.write("        [\"%s\"] = \"%s\",\n" % (header[0], header[1]))
        config.write("    },\n")
        config.write("    body = \"%s\",\n" % self.body)
        config.write("}\n")
        config.write("local req\n")
        config.write("init = function()\n")
        config.write("    req = wrk.format(r.method, r.path, r.headers, r.body)\n")
        config.write("end\n")
        config.write("request = function()\n")
        config.write("    return req\n")
        config.write("end\n")
        config.close()

    def remove_config(self):
        """ Remove previously created config """
        if self.filename != None:
            os.unlink(self.filename)
            self.filename = None
