#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

# It runs tests from 
# $ tempesta_fw/t/functional/tests.
# The names of the tests have to be in the __init__.py file in that directory.


import pkgutil
import tests

import subprocess
import sys
import os
from os.path import dirname, realpath, sep

sys.path.append((dirname(realpath(__file__))+ sep + "tests" + sep + "helpers"))


# For tests.py the root is on three levels up.
dir = dirname(realpath(__file__))
dir = dirname(dir)
dir = dirname(dir)
root = dirname(dir)
import conf
import teardown
conf.set_root(root) 

if len(sys.argv) > 1:
	argindex = 0
	for arg in sys.argv:
		if arg == '-p':
			conf.set_beport(int(sys.argv[argindex + 1]))
		argindex += 1
	for loader, name, ispkg in pkgutil.iter_modules(path = tests.__path__, 
							prefix = ''):
		if not ispkg:
			if (name == sys.argv[1]) | (sys.argv[1] == "all"):
				test = loader.find_module(name).load_module(name)
				tclass = getattr(test, 'Test')
				print("test:{}".format(tclass().get_name()))
				tclass().run()
				teardown.run()
				teardown.clean()
else:
	print("\n\nusage:\n test.py <test_name> or test.py all\n")
	os._exit(0)

		
