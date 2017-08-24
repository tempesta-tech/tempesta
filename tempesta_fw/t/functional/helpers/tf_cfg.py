""" Test framework configuration options.
"""

from __future__ import print_function, unicode_literals
import os
import sys
import configparser

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ConfigError(Exception):
    def __init__(msg):
        Exception.__init__("Test configuration error: %s" % msg)

class TestFrameworkCfg(object):

    cfg_file = os.path.relpath(os.path.join(
        os.path.dirname(__file__),
        '..',
        'tests_config.ini'
    ))

    def __init__(self, filename=None):
        if filename:
            self.cfg_file = filename
        self.defaults()
        self.cfg_err = None
        try:
            self.config.read(self.cfg_file)
        except:
            self.cfg_err = sys.exc_info()

    def defaults(self):
        self.config = configparser.ConfigParser()
        self.config.read_dict({'General': {'verbose': '0',
                                           'duration': '10',
                                           'concurrent_connections': '10'},
                               'Client': {'ip': '127.0.0.1',
                                          'hostname': 'localhost',
                                          'ab': 'ab',
                                          'wrk': 'wrk',
                                          'workdir': '/tmp/client'},
                               'Tempesta': {'ip': '127.0.0.1',
                                            'hostname': 'localhost',
                                            'user': 'root',
                                            'port': '22',
                                            'workdir': '/root/tempesta',
                                            'config': '/tmp/tempesta.conf'},
                               'Server': {'ip': '127.0.0.1',
                                          'hostname': 'localhost',
                                          'user': 'root',
                                          'port': '22',
                                          'nginx': 'nginx',
                                          'workdir': '/tmp/nginx',
                                          'resources': '/var/www/html/'}
                              })

    def inc_verbose(self):
        verbose = int(self.config['General']['Verbose']) + 1
        self.config['General']['Verbose'] = str(verbose)

    def set_duration(self, val):
        try:
            int(val)
        except ValueError:
            return False
        self.config['General']['Duration'] = val
        return True

    def get(self, section, opt):
        return self.config[section][opt]

    def get_binary(self, section, binary):
        if self.config.has_option(section, binary):
            return self.config[section][binary]
        return binary

    def save_defaults(self):
        self.defaults()
        with open(self.cfg_file, 'w') as configfile:
            self.config.write(configfile)
        print('Default configuration saved to %s' % self.cfg_file)

    def check(self):
        if self.cfg_err is not None:
            msg = ('unable to read "%s" (%s: %s)' %
                   (self.cfg_file,
                    self.cfg_err[0].__name__,
                    self.cfg_err[1]))
            raise ConfigError(msg), None, self.cfg_err[2]

        # normalize pathes
        normalize = [
                ('Client', 'workdir'),
                ('Tempesta', 'workdir'),
                ('Server', 'workdir'),
                ('Tempesta', 'config')
        ]
        for item in normalize:
            self.config[item[0]][item[1]] = os.path.normpath(self.config[item[0]][item[1]])

        #TODO: check configuration options
        client_hostname = self.config['Client']['hostname']
        if client_hostname != 'localhost':
            msg = ('running clients on a remote host "%s" is not supported' %
                   client_hostname)
            raise ConfigError(msg)

def debug():
    return int(cfg.get('General', 'Verbose')) >= 3

def v_level():
    return int(cfg.get('General', 'Verbose'))

def dbg(level, *args, **kwargs):
    if int(cfg.get('General', 'Verbose')) >= level:
        print(file=sys.stderr, *args, **kwargs)

cfg = TestFrameworkCfg()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
