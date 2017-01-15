#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'


import pkgutil
import tests
import subprocess
import sys
from os.path import dirname, realpath, sep

#sys.path.append('./tests/helpers')
sys.path.append((dirname(realpath(__file__))+ sep + "tests" + sep + "helpers"))

for loader, name, ispkg in pkgutil.iter_modules(path = tests.__path__, prefix = ''):
	if not ispkg:
		print(name)
		test = loader.find_module(name).load_module(name)
		tclass = getattr(test, 'Test')
		print("test:", tclass().get_name())
		tclass().run()
