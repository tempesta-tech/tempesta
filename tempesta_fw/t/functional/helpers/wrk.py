""" Wrk script generator """

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

from . import remote

class ScriptGenerator(object):
    """ Generate lua script """
    request_type = "GET"
    uri = "/"
    headers = []
    body = ""
    config = ""
    def __luaencode(self, value):
        # TODO: take care about escaping
        # if we have tests with special symbols in content
        return value

    def set_request_type(self, request_type):
        self.request_type = request_type

    def set_uri(self, uri):
        self.uri = uri

    def add_header(self, header_name, header_value):
        self.headers.append((header_name, header_value))

    def set_body(self, body):
        self.body = body

    def make_config(self):
        """ Generate config and write it to file """
        config = ""
        config += "wrk.method = \"%s\"\n" % self.request_type
        config +="wrk.path = \"%s\"\n" % self.__luaencode(self.uri)
        config += "wrk.headers = {\n"
        for header in self.headers:
            name = self.__luaencode(header[0])
            value = self.__luaencode(header[1])
            config += "    [\"%s\"] = \"%s\",\n" % (name, value)
        config += "},\n"
        config += "wrk.body = \"%s\",\n" % self.__luaencode(self.body)
        return config
