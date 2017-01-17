#!/usr/bin/env python

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2015-2017 Tempesta Technologies Inc.'
__license__ = 'GPL2'

# Functions after executing a test.

hooks = []

def register(func):
	global hooks
	hooks.append(func) 

def run():
	global hooks
	for func in hooks:
		if hasattr(func, '__call__'):
			func()

def clean():
	global hooks
	hooks = []
