#!/usr/bin/env python
__author__ = 'Tempesta Technologies'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'
import sys
from os.path import dirname, realpath, sep
import time
import types
sys.path.append(dirname(realpath(__file__))+ sep + sep + "helpers")

import conf
import tfw
from socket import *



def run():
	vs_get = "GET http://localhost:80/ HTTP/1.1\r\nHost: localhost\r\n\r\n"
	cfg = conf.Config("etc/tempesta_fw.conf")
	cfg.add_option('cache', '2')
	cfg.add_option('listen', '8081')
	cfg.add_option('server', '127.0.0.1:80')
	tfw.start()
	s = socket(AF_INET, SOCK_STREAM)
	s.connect(('127.0.0.1', 8081))
	s.send(vs_get)
	data = s.recv(1024)
	print(data)

run()
