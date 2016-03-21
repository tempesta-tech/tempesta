#!/usr/bin/env python3
import pkgutil
import tests
import subprocess
import sys

sys.path.append('/usr/src/projects/tempesta/tempesta_fw/t/functional/tests/helpers')

for loader, name, ispkg in pkgutil.iter_modules(path = tests.__path__, prefix = ''):
	if not ispkg:
		print(name, loader)
		test = loader.find_module(name).load_module(name)
		tclass = getattr(test, 'Test')
		print("test:", tclass().get_name())
		tclass().run()
