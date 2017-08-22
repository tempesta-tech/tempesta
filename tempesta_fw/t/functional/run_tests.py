#!/usr/bin/env python2
from __future__ import print_function
import unittest
import getopt
import sys
import os
import resource

from helpers import tf_cfg, remote, shell

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

Non-flag arguments may be used to include/exclude specific tests.
Specify a dotted-style name or prefix to include every matching test:
`cache.test_cache`, `flacky_net` (but not `sched.test_`).
Prefix an argument with `-` to exclude every matching test: `-cache.test_purge`,
`-flacky_net.test_sockets.CloseOnShutdown`.
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

if os.geteuid() != 0:
    raise Exception("Tests must be run as root.")

tf_cfg.cfg.check()

# Verbose level for unit tests must be > 1.
v_level = int(tf_cfg.cfg.get('General', 'Verbose')) + 1

# Install Ctrl-C handler for graceful stop.
unittest.installHandler()

#
# Process exclusions/inclusions/resumption
#

# process filter arguments
inclusions = []
exclusions = []
for name in remainder:
    # determine if this is an inclusion or exclusion
    if name.startswith('-'):
        name = name[1:]
        exclusions.append(name)
    else:
        inclusions.append(name)

#
# Discover tests, configure environment and run tests
#

print("""
----------------------------------------------------------------------
Running functional tests...
----------------------------------------------------------------------
""")

# For the sake of simplicity, Unconditionally discover all tests and filter them
# afterwards instead of importing individual tests by positive filters.
loader = unittest.TestLoader()
tests = []
shell.testsuite_flatten(tests, loader.discover('.'))

# Now that we initialized the loader, convert arguments to dotted form (if any).
for lst in (inclusions, exclusions):
    lst[:] = [shell.test_id_parse(loader, t) for t in lst]

# filter testcases
tests = [ t
          for t in tests
          if (not inclusions or shell.testcase_in(t, inclusions))
          and not shell.testcase_in(t, exclusions) ]

#
# Configure environment, connect to the nodes
#

# the default value of fs.nr_open
nofile = 1048576
resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))

remote.connect()

#
# Run the discovered tests
#

testsuite = unittest.TestSuite(tests)
testRunner = unittest.runner.TextTestRunner(verbosity=v_level,
                                            failfast=fail_fast,
                                            descriptions=False)
testRunner.run(testsuite)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
