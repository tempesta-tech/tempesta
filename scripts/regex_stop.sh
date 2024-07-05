#!/bin/bash

script_path="$(dirname $0)"

rm -f /tmp/tempesta/*.txt
rm -rf /tmp/tempesta/out
#rmdir -p /sys/kernel/config/rex/*
rmdir /sys/kernel/config/rex/*