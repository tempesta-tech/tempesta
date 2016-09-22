#!/usr/bin/env python
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 20115-2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

import conf
import tfw

c = conf.Config("etc/tempesta_fw.conf")

class Test:
	def get_name(self):
		return 'bomber'

	def run(self):
		c.add_option('cache', '0')
		c.add_option('listen', '8081')
		c.add_option('server', '127.0.0.1:80')
		tfw.start()
		print("tfw started\n")
		tfw.start_bomber()
		print("bomber started\n")
		tfw.stop()
		print("tfw stoped\n")

