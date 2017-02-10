import configparser
import os

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class TestFrameworkCfg():

    def __init__(self):
        self.defaults()
        config_path = os.path.dirname(os.path.realpath(__file__ + '/..'))
        self.config.read(config_path + '/tests_config.ini')

    def defaults(self):
        self.config = configparser.SafeConfigParser()
        self.config.read_dict({'General': {'verbose': '0',
                                           'duration': '10',
                                           'concurent_connections': '-1'},
                               'Client': {'ip': '127.0.0.1',
                                          'hostname': 'localhost',
                                          'user': 'root',
                                          'port': '22',
                                          'ab': 'ab',
                                          'wrk': 'wrk',
                                          'siege': 'siege',
                                          'workdir': '/root/client',},
                               'Tempesta': {'ip': '127.0.0.1',
                                            'hostname': 'localhost',
                                            'user': 'root',
                                            'port': '22',
                                            'dir': '/root/tempesta',},
                               'Server': {'ip': '127.0.0.1',
                                          'hostname': 'localhost',
                                          'user': 'root',
                                          'port': '22',
                                          'nginx': 'nginx',
                                          'workdir': '/root/nginx',
                                          'resourses': '/srv/http/'}
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
        #TODO: check configuration options
        return True


    def example(self):
        print(""" #Sample Test Frame work config file:

[General]
# Verbose level. 0 - Disabled, 1 - Show test names, 2 - Show performance and
# error counters, 3 - Full debug output.
verbose = 1
# Duration of every single test which uses HTTP benchmarks utilities, in seconds.
duration = 10

[Client]
# IP and of interface used for testing, both IPv4 and IPv6 are supported.
# The Test Suite inserts the value into TempestaFW
ip = 127.0.0.1
# SSH credentials for remote control.
hostname = localhost
user = root
port = 22
# Absolute path to Apache Benchmark binary.
ab = /usr/bin/ab
# Absolute path to wrk benchmark utility binary.
wrk = /usr/bin/wrk
# Absolute path to Siege benchmark utility binary.
siege = /usr/bin/siege

[Tempesta]
ip = 127.0.0.1
hostname = localhost
user = root
port = 22
# Absolute path to TempestaFW sources directory.
dir = /root/tempesta

[Server]
ip = 127.0.0.1
hostname = localhost
user = root
port = 22
# Absolute path to NGINX binary.
nginx = /usr/bin/nginx
# Absolute path to sample nginx root location. Must be reachable by nginx.
resourses = /srv/http/
        """)

def debug():
    return int(cfg.get('General', 'Verbose')) >= 3

def v_level():
    return int(cfg.get('General', 'Verbose'))

def dbg(*args, **kwargs):
    if (debug()):
        print(*args, **kwargs)

cfg = TestFrameworkCfg()
