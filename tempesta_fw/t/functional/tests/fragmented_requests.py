#!/usr/bin/env python

#A test for the Tempesta http parser with a request divided into chunks.
# We get a request, divide it into chunks, then send the chunks separately.
# Then check the Tempesta response.

__author__ = 'Temesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

import conf
import tfw
import socket
import tfwparser
import be
import datetime
class Test:
	def fragmentize_str(self, s, frag_size):
#		Split a string into a list of equal N-sized fragmen.
#		>>> fragmentize_str("foo12bar34baz", 3)
#		['foo', '12b', 'ar3', '4ba', 'z']
		return [s[i:i+frag_size]  for i in range(0, len(s), frag_size)]

	def run(self):
		req_get = 'GET http://github.com/natsys/tempesta HTTP/1.1\r\n'
		req_get += 'Host: github.com\r\n'
		req_get += 'User-Agent: Mozilla/5.0 (X11; Linux x86_64;'
		req_get += ' rv:31.0) Gecko/20100101 Firefox/31.0' 
		req_get += 'Iceweasel/31.2.0\r\n'
		req_get += 'Accept: text/html,application/xhtml+xml,'
		req_get += 'application/xml;q=0.9,*/*;q=0.8\r\n'
		req_get += 'Accept-Language: en-US,en;q=0.5\r\n'
		req_get += 'Accept-Encoding: gzip, deflate\r\n'
		req_get += 'Referer: http://natsys-lab.com/cgi-bin/show.pl'
		req_get += '\r\n\r\n'
		c = conf.TFWConfig()
		parser = tfwparser.TFWParser()
		c.add_option('cache', '0')
		c.add_option('listen', '8081')
		c.add_option('server', '127.0.0.1:80')
		body_md5 = ""
		tfw.start()
		print("tfw start\n")
		self.res = True
		
		fragment_size =1
		while fragment_size < len(req_get):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect(("127.0.0.1",8081))
			s.settimeout(1)
			for fs in self.fragmentize_str(req_get, fragment_size):
				s.sendall(fs)
			data = s.recv(1024)
			if len(data) == 0:
				self.res = False
			else:
				status = parser.get_status(data)
				if body_md5 == "":
					body_md5 = parser.get_body_hash(data)
				else:
					if parser.get_body_hash(data) !=\
					body_md5:
						print("body_hash not match \n")
						self.res = False
				if (status != 200) & (status != 404):
					print("status:{}\n".format(status))
					self.res = False
			s.close()
			fragment_size += 1
	
		s.close()
		tfw.stop()
		print("Res:{}\n".format(self.res))

	def get_name(self):
		return 'fragmented request'

