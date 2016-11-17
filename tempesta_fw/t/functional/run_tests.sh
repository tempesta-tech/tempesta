#!/bin/bash
# Copyright(C) 2014 Natsys Lab. (info@natsys-lab.com)
 #Copyright(C) 2015 - 2016. Tempesta Technologies Inc.

function run() {
	echo run: $1
	$(dirname $0)/$1
	if [ $? -ne 0 ]
	then
		echo FAILED: $1
		exit -1
	fi
}
if [$1 == ""]; then
echo -e "Bad parameters:\nusage:\nrun_tests.sh <test_name>\nor run_tests.sh all\n"
else
$(dirname $0)/tests.py $@
#echo
#echo ------------------------------------------------------------------
#echo Running functional tests...
#echo ------------------------------------------------------------------
 
#run tests.py $1
fi
