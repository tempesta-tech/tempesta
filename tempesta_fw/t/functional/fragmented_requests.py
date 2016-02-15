#!/usr/bin/env python3

from helpers import *

__author__ = 'NatSys Lab'
__copyright__ = 'Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).'
__license__ = 'GPL2'

req_get = '''\
GET http://github.com/natsys/tempesta HTTP/1.1\r \
Host: github.com\r
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 \
Firefox/31.0 Iceweasel/31.2.0\r \
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r \
Accept-Language: en-US,en;q=0.5\r \
Accept-Encoding: gzip, deflate\r \
DNT: 1\r \
Referer: http://natsys-lab.com/cgi-bin/show.pl\r \
Cookie: logged_in=yes; _ga=GA1.2.1404175546.1417001200; \
user_session=EdI8qD-H305ePHXkP13VfCIDNAKgSSxdEGq25wtENSwxsxRKJVIDstdZLU_ \
9EYy68Dj7jBKVtF9G9Kxel; dotcom_user=vdmit11; _octo=GH1.1.1046670168.1410702951; \
 _gh_sess=eyJzZXNba9WuX2lkIjoiMDY5ZmM5MGFmMTFjZDgxZTIxNzY0MTNlM2M3YzBmmMIiLCJz \
cHlfcmVwbyI6Im5hdHN5cy90ZW1ZwXN0YSIsInNweV9yZXBvX2F0IjoxNDE3NzM1MzQ5LCJjb250ZX \
h0IjoiLyIsImxhc3Rfd3JpdGUijOE9MTc3MzUzNDk3NDN7--eed6d44a1be9e83a34dbf8d5e319a5 \
20f30fa481; tz=Europe%2FMoscow; _gat=1\r
Connection: Keep-Alive\r
Cache-Control: max-age=0\r
'''

def validate_received_req_get(method, path, headers, body):
	assert method == 'GET'
	assert path == 'http://github.com/natsys/tempesta'
	assert len(body) == 0
	h = {
 	'Host': 'github.com',
	'User-Agent': '''Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko \
010101 Firefox/31.0 Iceweasel/31.2.0''',
	'Accept': '''text/html,application/xhtml+xml,application/xml;q=0.9,\
*/*; q= .8''',
	'Accept-Language': 'en-US,en;q=0.5',
	'Accept-Encoding': 'gzip, deflate',
'DNT': '1',
	'Referer': 'http://natsys-lab.com/cgi-bin/show.pl',
	'Cookie': ''''logged_in=yes; _ga=GA1.2.1404175546.1417001200; \
user_session=EdI8qD-H305ePHXkP13VfCIDNAKgSSxdEGq25wtENSwxsxRKJVIDstdZLU9EYy68D \
j7jBKVtF9G9Kxel; dotcom_user=vdmit11; _octo=GH1.1.1046670168.1410702951; \
_gh_sess=eyJzZXNba9WuX2lkIjoiMDY5ZmM5MGFmMTFjZDgxZTIxNzY0MTNlM2M3YzBmmMIiLCJz \
cHlfcmVwbyI6Im5hdHN5cy90ZW1ZwXN0YSIsInNweV9yZXBvX2F0IjoxNDE3NzM1MzQ5LCJjb250Z \
Xh0IjoiLyIsImxhc3Rfd3JpdGUijOE9MTc3MzUzNDk3NDN7--eed6d44a1be9e83a34dbf8d5e319 \
a520f30fa481; tz=Europe%2FMoscow; _gat=1''',
        'Connection': 'Keep-Alive',
	'Cache-Control': 'max-age=0',
}

	for k in h.keys():
		if h[k] != headers[k]:
			msg = "Expected: %s, got: %s" % (h[k], headers[k])
			raise Error(msg)

def fragmentize_str(s, frag_size):
	"""
	Split a string into a list of equal N-sized fragmen.
	>>> fragmentize_str("foo12bar34baz", 3)
	['foo', '12b', 'ar3', '4ba', 'z']
	"""
	return [s[i:i+frag_size]  for i in range(0, len(s), frag_size)]

	backend_callback_counter = 0

def backend_callback(method, path, headers, body):
	++backend_callback_counter;
	validate_received_req_get(method, path, headers, body)
	return 200, { 'Content-Type': 'text/plan' }, 'Everything is OK.'

# Start Tempesta FW and a back-end server with a default configuration.
def run_test():
	c = Config('etc/tempesta.conf')
	c.add_option('listen', '8081')
	c.add_option('server', '127.0.0.1:8080')
	tfw.start()
	be.start(backend_callback)

# The test body:
#
# In the real world, HTTP messages, especially big ones, are often fragmented
# (because of network MTU/MRU, TCP MSS, application buffer sizes, etc).
# Fragments of the same HTTP request may have different sizes and arrive to
# server at different time.
#
# The goal here is to simulate such situation and check that the parser of
# Tempesta FW can handle messages broken to any number of such fragments.
#
# We would like to go the most extreme case: split the request to 1-byte chunks
# to check that a gap may occur at any position of the message.
# But Tempesta FW assumes (for optimization purposes) that first few bytes are
# continuous (and indeed in the real world they are), so we put them as a solid
# fragment, and split the rest of the message to single characters.
#
# So in the end we should get the following fragments sent to the server:
# [ 'GET http://', 'g', 'i', 't', 'h', 'u', 'b', '.', 'c', 'o', 'm', ... ]


	with cli.connect_to_tfw() as socket:
		socket.sendall(bytes(req_get, 'UTF-8'))
    # wait for a response from Tempesta, just receive anything, we don't care what
		socket.recv(1)
	assert backend_callback_counter == 1

