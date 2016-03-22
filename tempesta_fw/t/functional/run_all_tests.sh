#!/bin/bash
#
# 2012-2016. Written by NatSys Lab. (info@natsys-lab.com).

function run() {
	echo run: $1
	$(dirname $0)/$1
	if [ $? -ne 0 ]
	then
		echo FAILED: $1
		exit -1
	fi
	echo PASSED: $1 
}

echo
echo ------------------------------------------------------------------
echo Running functional tests...
echo ------------------------------------------------------------------
 
run bomber.py 
