#!/usr/bin/env python
class Config:
	name = '/etc/tempesta_fw.conf'

	def __init__(self, name):
		self.name = name
		open(self.name, "w")
		return
	def add_option(self, option, value):
		with open(self.name, "a+") as conf:
			conf.write(option + ' ' + value + ';\n')


