#!/bin/bash
#
# A script that simply runs all tests for Tempesta FW.
#
# 2012-2014. Written by NatSys Lab. (info@natsys-lab.com).



function run_test_mod() {
	insmod $(dirname $0)/tfw_test.ko
	rmmod tfw_test
}

function show_last_run_log() {
	dmesg | tac | grep -m 1 -B 200 "tfw_test: start" | tac
}

function show_last_run_summary() {
	show_last_run_log | grep "tfw_test: " | grep -v "tfw_test: TEST_RUN"
}

function echo_header() {
	echo
	echo ------------------------------------------------------------------------
	echo $@
	echo ------------------------------------------------------------------------
}


echo_header Running tests...
run_test_mod

echo_header Test run full log:
show_last_run_log

echo_header Test run summary:
show_last_run_summary