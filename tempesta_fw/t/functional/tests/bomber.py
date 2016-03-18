#!/usr/bin/env python3
from helpers import conf
from helpers import tfw

c = conf.Config("etc/tempesta_fw.conf")

class Test:
	def get_name():
		return 'bomber'

def run():
	c.add_option('cache', '0')
	c.add_option('listen', '8081')
	c.add_option('server', '127.0.0.1:80')
	tfw.start()
	print("tfw started\n")
	tfw.start_bomber()
	print("bomber started\n")
	tfw.stop()
	print("tfw stoped\n")

run()
