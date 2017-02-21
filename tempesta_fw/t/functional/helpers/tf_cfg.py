from __future__ import print_function, unicode_literals
import configparser, os, sys

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestFrameworkCfg():

    def __init__(self, cfg_file):
        self.defaults()
        self.file_err = True
        if os.path.isfile(cfg_file):
            self.file_err = False
            self.config.read(cfg_file)

    def defaults(self):
        self.config = configparser.ConfigParser()
        self.config.read_dict({'General': {'verbose': '0',
                                           'duration': '10',
                                           'concurrent_connections': '10'},
                               'Client': {'ip': '127.0.0.1',
                                          'hostname': 'localhost',
                                          'user': 'root',
                                          'port': '22',
                                          'ab': 'ab',
                                          'wrk': 'wrk',
                                          'siege': 'siege',
                                          'workdir': '/tmp/client',},
                               'Tempesta': {'ip': '127.0.0.1',
                                            'hostname': 'localhost',
                                            'user': 'root',
                                            'port': '22',
                                            'workdir': '/root/tempesta',},
                               'Server': {'ip': '127.0.0.1',
                                          'hostname': 'localhost',
                                          'user': 'root',
                                          'port': '22',
                                          'nginx': 'nginx',
                                          'workdir': '/tmp/nginx',
                                          'resources': '/var/www/html/'}
                               })

    def inc_verbose(self):
        v_level = int(self.config['General']['Verbose']) + 1
        self.config['General']['Verbose'] = str(v_level)

    def set_duration(self, val):
        try:
            seconds = int(val)
        except ValueError:
            return False
        self.config['General']['Duration'] = val
        return True

    def get(self, type, opt):
        return self.config[type][opt]

    def get_binary(self, type, bin):
        if self.config.has_option(type, bin):
            return self.config[type][bin]
        else:
            return bin

    def save_defaults(self):
        self.defaults()
        with open('tests_config.ini', 'w') as configfile:
            self.config.write(configfile)

    def check(self):
        if self.file_err:
            return False, 'Configuration file "tests_config.ini" not found.'
        #TODO: check configuration options
        for host in ['Client', 'Tempesta', 'Server']:
            if not self.config[host]['workdir'].endswith('/'):
                self.config[host]['workdir'] += '/'

        if self.config['Client']['hostname'] != 'localhost':
            return False, "Running clients on remote host is not supported yet."
        return True, ''

def debug():
    return int(cfg.get('General', 'Verbose')) >= 3

def v_level():
    return int(cfg.get('General', 'Verbose'))

def dbg(level, *args, **kwargs):
    if (int(cfg.get('General', 'Verbose')) >= level):
        print(*args, **kwargs)

cfg_file = ''.join([os.path.dirname(os.path.realpath(__file__)),
                    '/../tests_config.ini'])
cfg = TestFrameworkCfg(cfg_file)

r, reason = cfg.check()
if not r:
    print("Error:", reason)
    sys.exit(1)
