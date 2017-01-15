#!/usr/bin/env python
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

import os
import fileinput
class Config:
	name = '/etc/tempesta_fw.conf'
	tmpname = 'etc/temp.conf'

	def __init__(self, name):
		self.name = name
		open(self.name, "w")
		return

	def add_option(self, option, value):
		with open(self.name, "a+") as conf:
			conf.write(option + ' ' + value + ';\n')
	def add_section(self, section):
		with open(self.name, "a+") as conf:
			conf.write(section + '{\n')

	def add_end_of_section(self):
		with open(self.name, "a+") as conf:
			conf.write('}')

	def del_option(self, option):
		temp = open(self.tmpname, 'a+')
		for line in fileinput.input(self.name):
			if not option in line:
				temp.write(line)

		os.rename(self.tmpname, self.name)
