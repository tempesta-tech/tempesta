#!/usr/bin/env python3
import subprocess
__author__ = 'NatSys Lab'
__copyright__ = 'Copyright (C) 2016 NatSys Lab. (info@natsys-lab.com).'
__license__ = 'GPL2'

def start():
	subprocess.call("service apache2 start", shell = True)
