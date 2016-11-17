#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

from HTMLParser import HTMLParser
import re
import hashlib
import subprocess
import shlex

class TFWParser(HTMLParser):
	CRLFCRLF = "\r\n\r\n"
	status = ""
	def get_body_hash(self, data):
		body = self.get_body(data)
		hasher = hashlib.md5()
		hasher.update(body)
		hres = hasher.hexdigest()
		return hres

	def get_body(self, data):
		bstart = data.find(self.CRLFCRLF)
		bstart += len(self.CRLFCRLF) 
		bstop = data.find(self.CRLFCRLF, bstart)
		if bstop == -1:
			bstop = len(data)
		bres = data[bstart:bstop]
		return bres

	def set_status(self, data):
		status = re.findall("\d\d\d", data)
		if len(status) > 0:
			self.status = status[0]

	def get_status(self, data):
		self.set_status(data)
		return int(self.status)

	def check_cache_stat(self):
		from_cache = 0 
		p1 = subprocess.Popen(shlex.split("cat /proc/tempesta/perfstat"),
				     stdout=subprocess.PIPE)
		p2 = subprocess.Popen(shlex.split("grep cache"), 
					stdin=p1.stdout,
					stdout=subprocess.PIPE)
		out = p2.stdout.read()
		re_stat = re.findall("\d", out)
		from_cache = int(re_stat[0]) 
		
		return from_cache 
	
	def check_log(self, substr):
		p1 = subprocess.Popen(shlex.split("dmesg"),
				      stdout=subprocess.PIPE)
		p2 = subprocess.Popen(shlex.split("grep \'" + substr + '\''),
				      stdin=p1.stdout,
				      stdout=subprocess.PIPE)
		out = p2.stdout.read()
		if out.find(substr) > 0:
			return True
