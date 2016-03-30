#!/usr/bin/env python

__author__ = 'Temesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies Inc. (info@natsys-lab.com).'
__license__ = 'GPL2'

import conf
import tfw
import socket

req_get = b'\
GET / HTTP/1.1\r\
Host: github.com\r\
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 \
Firefox/31.0 Iceweasel/31.2.0\r\
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\
Accept-Language: en-US,en;q=0.5\r\
Accept-Encoding: gzip, deflate\r\
DNT: 1\r\
Referer: http://natsys-lab.com/cgi-bin/show.pl\r\
Cookie: logged_in=yes; _ga=GA1.2.1404175546.1417001200;\
user_session=EdI8qD-H305ePHXkP13VfCIDNAKgSSxdEGq25wtENSwxsxRKJVIDstdZLU_\
9EYy68Dj7jBKVtF9G9Kxel; dotcom_user=vdmit11; _octo=GH1.1.1046670168.1410702951;\
 _gh_sess=eyJzZXNba9WuX2lkIjoiMDY5ZmM5MGFmMTFjZDgxZTIxNzY0MTNlM2M3YzBmmMIiLCJz\
cHlfcmVwbyI6Im5hdHN5cy90ZW1ZwXN0YSIsInNweV9yZXBvX2F0IjoxNDE3NzM1MzQ5LCJjb250ZX \
h0IjoiLyIsImxhc3Rfd3JpdGUijOE9MTc3MzUzNDk3NDN7--eed6d44a1be9e83a34dbf8d5e319a5 \
20f30fa481; tz=Europe%2FMoscow; _gat=1\r\
Connection: Keep-Alive\r\
Cache-Control: max-age=0\r\
'

def validate_received_req_get(method, path, headers, body):
	assert method == 'GET'
	assert path == 'http://github.com/natsys/tempesta'
	assert len(body) == 0
	h = {
 	'Host': 'github.com',
	'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko \
010101 Firefox/31.0 Iceweasel/31.2.0',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,\
*/*; q= .8',
	'Accept-Language': 'en-US,en;q=0.5',
	'Accept-Encoding': 'gzip, deflate',
'DNT': '1',
	'Referer': 'http://natsys-lab.com/cgi-bin/show.pl',
	'Cookie': 'logged_in=yes; _ga=GA1.2.1404175546.1417001200; \
user_session=EdI8qD-H305ePHXkP13VfCIDNAKgSSxdEGq25wtENSwxsxRKJVIDstdZLU9EYy68D \
j7jBKVtF9G9Kxel; dotcom_user=vdmit11; _octo=GH1.1.1046670168.1410702951; \
_gh_sess=eyJzZXNba9WuX2lkIjoiMDY5ZmM5MGFmMTFjZDgxZTIxNzY0MTNlM2M3YzBmmMIiLCJz \
cHlfcmVwbyI6Im5hdHN5cy90ZW1ZwXN0YSIsInNweV9yZXBvX2F0IjoxNDE3NzM1MzQ5LCJjb250Z \
Xh0IjoiLyIsImxhc3Rfd3JpdGUijOE9MTc3MzUzNDk3NDN7--eed6d44a1be9e83a34dbf8d5e319 \
a520f30fa481; tz=Europe%2FMoscow; _gat=1',
        'Connection': 'Keep-Alive',
	'Cache-Control': 'max-age=0',
}

	for k in h.keys():
		if h[k] != headers[k]:
			msg = "Expected: %s, got: %s" % (h[k], headers[k])
			raise Error(msg)

backend_callback_counter = 0

def fragmentize_str(s, frag_size):
	"""
	Split a string into a list of equal N-sized fragmen.
	>>> fragmentize_str("foo12bar34baz", 3)
	['foo', '12b', 'ar3', '4ba', 'z']
	"""
	return [s[i:i+frag_size]  for i in range(0, len(s), frag_size)]


def backend_callback(method, path, headers, body):
	backend_callback_counter += 1
	validate_received_req_get(method, path, headers, body)
	return 201, { 'Content-Type': 'text/plan' }, 'Everything is OK.'

# Start Tempesta FW and a back-end server with a default configuration.
def run():
	c = conf.Config('etc/tempesta_fw.conf')
	c.add_option('cache', '0')
	c.add_option('listen', '8081')
	c.add_option('server', '127.0.0.1:80')

	vs_get = b"GET / HTTP/1.0\r\nhost: loc\r\n\r\n"
	s_get = b"GET http:localhost:80/index.html HTTP/1.0\r\n\
Connection: Keep-Alive\r\n\
host: localhost\r\n\r\n"
	tfw.start()
	print("tfw start\n")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("127.0.0.1",8081))
	s.sendall(vs_get)
	data = s.recv(1024)
	print("rec:", data)
	tfw.stop()
	s.close()
	print("Ok\n")

class Test:

	def run(self):
		run()

	def get_name(self):
		return 'fragmented_requests'
