#!/usr/bin/env python
__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'
import sys
from os.path import dirname, realpath, sep

sys.path.append((dirname(realpath(__file__))+ sep + "helpers"))
import conf
import tfw
import socket

def run():
	vs_get = b"POST /index.html HTTP/1.0\r\nHost: loc\r\n" +\
	b"\r\nTransfer-Encoding: chunked\r\nConnection: Keep-Alive\r\n" +\
b"\r\nContent-type: html\r\nContent-Length: 0" +\
b"\r\n<html>content</html>\r\n\r\n"
	c = conf.Config('etc/tempesta_fw.conf')
	c.add_option('cache', '0')
	c.add_option('listen', '8081')
	c.add_option('server', '127.0.0.1:80')
	tfw.start()
	print("tfw start\n")
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("127.0.0.1",8081))
	s.sendall(vs_get)
	data = s.recv(1024)
	print("recv:", data)
	s.close()
	tfw.stop()
	
	
run()   
	
	


