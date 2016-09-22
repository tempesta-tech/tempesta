#!/usr/bin/env python3

__author__ = 'Tempesta Technologies Inc.'
__copyright__ = 'Copyright (C) 2016 Tempesta Technologies. (info@natsys-lab.com).'
__license__ = 'GPL2'

import subprocess

def start():
	subprocess.call("service apache2 start", shell = True)
