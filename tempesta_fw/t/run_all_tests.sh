#!/bin/bash
#
# A script that simply runs all tests for Tempesta FW.
#
# 2012-2014. Written by NatSys Lab. (info@natsys-lab.com).

insmod $(dirname $0)/tfw_test.ko
rmmod tfw_test
dmesg | tac | grep -m 1 -B 200 "tfw_test: start" | tac
