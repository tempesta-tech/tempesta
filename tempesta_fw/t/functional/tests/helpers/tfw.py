#!/usr/bin/env python

"""
Helpers for interacting with Tempesta FW (start/stop, configure, etc).
"""

import os
import subprocess
import sys
import conf

__author__ = 'NatSys Lab'
__copyright__ = 'Copyright (C) 22014 NatSys Lab. (info@natsys-lab.com).\
2015-2017 Tempesta Technologies Inc.'
__license__ = 'GPL2'

_tempesta_dir = conf.get_root()
def start():
	_sh(_tempesta_dir + '/scripts/tempesta.sh --start')

def start_with_frang():
	_sh(_tempesta_dir + '/scripts/tempesta.sh -f --start')

def stop():
	_sh("./scripts/tempesta.sh --stop")

def _sh(command):
	return subprocess.check_output(command, shell=True, cwd=_tempesta_dir)

def _is_started():
	return (0 == subprocess.call("lsmod | grep -q tempesta", shell=True))

def _stop_if_started():
	if (_is_started()):
		stop()
 	"""Ensure we start and stop in a pristine environment."""
	assert (not _is_started())

def start_bomber():
	_sh("./scripts/tfw_bomber.sh --start")

def stop_bomber():
	_sh("./scripts/tfw_bomber.sh --stop")
		
def del_db():
	"""Sometines we need after a test to remove information about blocked
	ips.
	"""
	_sh("rm -rf /opt/tempesta/db")
