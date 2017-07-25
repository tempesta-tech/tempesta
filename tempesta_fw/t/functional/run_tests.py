#!/usr/bin/env python2
from __future__ import print_function
import unittest
import getopt
import sys

# Disable configuration check for now and call it explicitly later
from helpers.tf_cfg import skip_check
skip_check = True

from helpers import tf_cfg, remote

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def usage():
    print("""
Functional tests for TempestaFW.

Test Framework Configuration is stored in 'tests_config.ini', Use '-d' option
to get defaults. Normally 3 machines are used to run tests: one to run HTTP
clients, second for TempestaFw it self and third one for HTTP servers. Running
tests on localhost is possible but not recommended for development environment.

Remote nodes controlled via SSH protocol. Make sure that you can be autorised by
key, not password. `ssh-copy-id` can be used for that.

-h, --help                        - Print this help and exit.
-v, --verbose                     - Enable verbose output.
-d, --defaults                    - Save defaut configuration to config file
                                    and exit.
-t, --duration <seconds>          - Duration of every single test.
-f, --failfast                    - Stop tests after first error.
""")

fail_fast = False

try:
    options, remainder = getopt.getopt(sys.argv[1:], 'hvdt:f',
                                       ['help', 'verbose', 'defaults',
                                        'duration=', 'failfast'])

except getopt.GetoptError as e:
    print(e)
    usage()
    sys.exit(2)

for opt, arg in options:
    if opt in ('-f', '--failfast'):
        fail_fast = True
    if opt in ('-v', '--verbose'):
        tf_cfg.cfg.inc_verbose()
    if opt in ('-t', '--duration'):
        if not tf_cfg.cfg.set_duration(arg):
            print('Invalid option: ', opt, arg)
            usage()
            sys.exit(0)
    elif opt in ('-d', '--save'):
        tf_cfg.cfg.save_defaults()
        sys.exit(0)
    elif opt in ('-h', '--help'):
        usage()
        sys.exit(0)

tf_cfg.cfg.check()

# Verbose level for unit tests must be > 1.
v_level = int(tf_cfg.cfg.get('General', 'Verbose')) + 1

# Install Ctrl-C handler for graceful stop.
unittest.installHandler()

print("""
----------------------------------------------------------------------
Running functional tests...
----------------------------------------------------------------------
""")

remote.connect()

#run tests
loader = unittest.TestLoader()
if not remainder:
    tests = loader.discover('.')
else:
    tests = loader.loadTestsFromNames(remainder)

testRunner = unittest.runner.TextTestRunner(verbosity=v_level,
                                            failfast=fail_fast,
                                            descriptions=False)
testRunner.run(tests)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
