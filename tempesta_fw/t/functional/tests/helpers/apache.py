#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016-2017 Tempesta Technologies.'
__license__ = 'GPL2'

import subprocess

def link_vhost(name):
	p = subprocess.Popen(["ln", "-s", "/etc/apache2/sites-available/" 
+ name, "/etc/apache2/sites-enabled"], stdout=subprocess.PIPE)


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

def stop():
	distr = get_dist()
	if is_apache():
		if distr == "debian":
			subprocess.call("service apache2 stop", shell = True)
		elif distr == "centos":
			subprocess.call("service httpd stop", shell = True)

	else:
		print("apache is not installed\n")

def start():
	distr = get_dist()
	if is_apache():
		if distr == "debian":
			subprocess.call("service apache2 start", shell = True)
		elif distr == "centos":
			subprocess.call("service httpd start", shell = True)

	else:
		print("apache is not installed\n")
	p = subprocess.Popen(["ab", "http://127.0.0.1:8081/"], stdout=subprocess.PIPE)
	out = p.stdout.read()
	if len(out) > 0:
		for s in out.split('\n'):
			print(s)

def run_ab():
	p = subprocess.Popen(["ab", "-n 10", "http://127.0.0.1:8081/"],
			     stdout=subprocess.PIPE)
	out = p.stdout.read()
	for line in out.split('\n'):
		print(line)



