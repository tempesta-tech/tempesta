#!/usr/bin/env python3
import pkgutil


for loader, name, ispkg in pkgutil.iter_modules(path = None, prefix = ''):
#	print(name, ispkg)
	if not ispkg:
		test = __import__(name)
		tclass = getattr(test, 'Test')
		print("test:", name, tclass.get_name())
		tclass().run()
