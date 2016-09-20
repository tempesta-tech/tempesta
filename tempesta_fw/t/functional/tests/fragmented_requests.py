#!/usr/bin/env python

__author__ = 'Temesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

import conf
import tfw
import socket
class Test:
	def fragmentize_str(self, s, frag_size):
		"""
		Split a string into a list of equal N-sized fragmen.
		>>> fragmentize_str("foo12bar34baz", 3)
		['foo', '12b', 'ar3', '4ba', 'z']
		"""
		return [s[i:i+frag_size]  for i in range(0, len(s), frag_size)]

	def run(self):
		c = conf.Config('etc/tempesta_fw.conf')
		c.add_option('cache', '0')
		c.add_option('listen', '8081')
		c.add_option('server', '127.0.0.1:80')
		vs_get = b"GET / HTTP/1.0\r\nhost: localhost\r\n\r\n"
		tfw.start()
		print("tfw start\n")
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(("127.0.0.1",8081))
		for fs in self.fragmentize_str(vs_get, 3):
			s.sendall(fs)
		data = s.recv(1024)
		tfw.stop()
		s.close()
		if len(data) > 0:
			print("Res:{}\n".format(True))

	def get_name(self):
		return 'fragmented request'

