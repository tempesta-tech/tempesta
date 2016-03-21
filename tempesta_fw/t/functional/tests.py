#!/usr/bin/env python3
__author__ = 'NatSys Lab'
__copyright__ = 'Copyright (C) 2016 NatSys Lab. (info@natsys-lab.com).'
__license__ = 'GPL2'


import pkgutil
import tests
import subprocess
import sys

sys.path.append('/usr/src/projects/tempesta/tempesta_fw/t/functional/tests/helpers')

for loader, name, ispkg in pkgutil.iter_modules(path = tests.__path__, prefix = ''):
	if not ispkg:
		print(name)
		test = loader.find_module(name).load_module(name)
		tclass = getattr(test, 'Test')
		print("test:", tclass().get_name())
		tclass().run()
