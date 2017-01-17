#!/usr/bin/env python

# A test just run bomber script on the Tempesta.
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 20115-2017 Tempesta Technologies Inc.'
__license__ = 'GPL2'

import conf
import tfw

c = conf.TFWConfig()

class Test:
	def get_name(self):
		return 'bomber'

	def run(self):
		""" The functions sets a simple configuration and starts 
		the Tempesta. Then it starts the bomber script. If the bomber
		runs without errors, then this simple test is passed.
		"""
		c.add_option('cache', '0')
		c.add_option('listen', '8081')
		c.add_option('server', '127.0.0.1:80')
		tfw.start()
		print("tfw started\n")
		tfw.start_bomber()
		print("bomber started\n")
		tfw.stop()
		print("tfw stoped\n")

