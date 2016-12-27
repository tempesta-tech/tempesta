#!/usr/bin/env python
__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc.'
__license__ = 'GPL2'

import os
from os.path import dirname, realpath
import fileinput

be_port = 0
tempesta_root = ""

def set_root(_root):
	global tempesta_root
	tempesta_root = _root

def get_root():
	global tempesta_root
	if tempesta_root == "":
		dir = dirname(realpath(__file__))
		dir = dirname(dir)
		dir = dirname(dir)
		dir = dirname(dir)
		dir = dirname(dir)
		root = dirname(dir)
		tempesta_root = root
	return tempesta_root 

def set_beport(_port):
	global be_port
	be_port = _port 

def get_beport():
	global be_port
	if be_port == 0:
		be_port = 8080
	return be_port

class Config:
	name = ''
	tmpname = get_root() + '/etc/temp.conf'

	def __init__(self, name, new=True):
		self.name = name
		if new == False:
			open(self.name, "a+")
		else:
			open(self.name, "w")
		return

	def add_option(self, option, value):
		with open(self.name, "a+") as conf:
			conf.write(option + ' ' + value + ';\n')

	def add_section(self, section):
		with open(self.name, "a+") as conf:
			conf.write(section + '{\n')
	def add_string(self, str):
		with open(self.name, "a+") as conf:
			conf.write('\n' + str)

	def add_end_of_section(self):
		with open(self.name, "a+") as conf:
			conf.write('}')

	def del_option(self, option):
		temp = open(self.tmpname, 'w')
		for line in fileinput.input(self.name):
			if not option in line:
				temp.write(line)

		os.rename(self.tmpname, self.name)

class TFWConfig(Config):
	def __init__(self):
		Config.__init__(self,get_root() + '/etc/tempesta_fw.conf', 
				new=True)

class ApacheConfig(Config):
	def __init__(self):
		Config.__init__(self, '/etc/apache2/apache2.conf', new=False)
