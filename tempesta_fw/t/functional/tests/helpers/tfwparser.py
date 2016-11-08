#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

from HTMLParser import HTMLParser
import re

class TFWParser(HTMLParser):
	status = ""
	def set_status(self, data):
		status = re.findall("\d\d\d", data)
		if len(status) > 0:
			self.status = status[0]

	def get_status(self):
		return self.status	

	def handle_data(self, data):
		if data[0] == 'H':
			self.set_status(data)

