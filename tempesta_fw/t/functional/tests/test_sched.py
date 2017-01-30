#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016-2017 Tempesta Technologies.'
__license__ = 'GPL2'

# #659 A functional test of schedulers of the Tempesta.

import time
import apache
import conf
import tfw
class Test:
	vh_curr = 1
	sg_curr = 1
	def __init__(self):
		self.cfg = conf.TFWConfig()
		self.apache_cfg = conf.ApacheConfig()
		self.cfg.add_option('listen', '8081')

	def add_sg(self, h_num, sched='round-robin'):
		""" The function adds a srv_group section with h_num servers
		to a Tempesta configuration. The Servers are virtual hosts of
		the Apache configuration.
		"""
		self.cfg.add_string("")
		self.cfg.add_section('srv_group '  + 'group' +
				     str(self.sg_curr) + ' sched=' + sched)
		for x in range(0, h_num):
			h_name = 'sched_' + str(self.vh_curr) + '.org'
			port = self.apache_cfg.add_vhost(h_name)
			self.cfg.add_option('server', '127.0.0.1:' + str(port))
			self.vh_curr += 1
		self.cfg.add_end_of_section()
		self.cfg.add_string("")
		
		self.sg_curr += 1

	def add_rules(self,host='sched'):
		self.cfg.add_string("")
		self.cfg.add_section('sched_http_rules')
		for x in range(1, self.sg_curr):
			if x == 1:
				self.cfg.add_option('match ' + 'group' + 
					    	    str(x), ' * * *')
			self.cfg.add_option('match ' + 'group' + 
					    str(x),' host eq '+
					    host + str(x))
		self.cfg.add_end_of_section()
	
	def run(self):
		"""The function adds 100 server groups with 2 servers for group.
		Then it adds rules for the groups, starts the Tempesta, then
		runs the ab(Apache Benchmark), prints its output.
		"""
		for x in range(1, 100):
			self.add_sg(2)
		self.add_rules('sched')
		apache.stop()
		apache.start()
		tfw.start()
		print("tfw started")
		apache.run_ab()
		time.sleep(20)
		tfw.stop()
	
	def get_name(self):
		return 'test schedulers'
