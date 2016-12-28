#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

from HTMLParser import HTMLParser
import re
import hashlib

class TFWParser(HTMLParser):
	status = ""
	def get_body_hash(self, data):
		body = self.get_body(data)
		hasher = hashlib.md5()
		hasher.update(body)
		hres = hasher.hexdigest()
		return hres

	def get_body(self, data):
		bstart = data.find('<html>')
		bstop = data.find('</html>')
		bstop += len('</html>')
		bres = data[bstart:bstop]
		return bres

	def set_status(self, data):
		status = re.findall("\d\d\d", data)
		if len(status) > 0:
			self.status = status[0]

	def get_status(self, data):
		self.set_status(data)
		return self.status	
