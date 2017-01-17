#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016-2017 Tempesta Technologies.'
__license__ = 'GPL2'

import subprocess

def is_apache():
	try:
		dist = get_dist()
		if dist == "debian":
			p = subprocess.Popen(["apache2", "-v"], 
					     stdout=subprocess.PIPE)
		elif dist == "centos":
			p = subprocess.Popen(["httpd", "-v"], 
					     stdout=subprocess.PIPE)
	except OSError as e:
		if e.errno == 2: 
			return False
	out = p.stdout.read()
	print("out:{}".format(out))
	if out.find("not found") > 0:
		return False
	else:
		return True

def get_dist():
	p = subprocess.Popen(["cat", "/etc/os-release"], stdout=subprocess.PIPE)
	out = p.stdout.read()
	if out.find("ID=debian") > 0:
		return "debian"
	else:
		if out.find("ID=\"centos\"") > 0:
			return "centos"

def start():
	distr = get_dist()
	if is_apache():
		if distr == "debian":
			subprocess.call("service apache2 start", shell = True)
		elif distr == "centos":
			subprocess.call("service httpd start", shell = True)

	else:
		print("apache is not installed\n")
