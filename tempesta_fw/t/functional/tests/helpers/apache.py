#!/usr/bin/env python3
import subprocess

def start():
	subprocess.call("service apache2 start", shell = True)
