#!/bin/bash

# Script to enable RSS on networking devices.
#
# Copyright (C) 2015-2024 Tempesta Technologies, Inc.
#
# For a regular Tempesta FW start we enable RSS in tempesta.sh script by default.
# This script may be needed for our test framework, where we start-stop the Tempesta FW for an every test,
# and enabling RSS for many devices many times may take a lot of time.
# So, we may run the script one time before running the whole test suite and after that we may start
# the Tempesta with option `--start --no-rss`.

. "$(dirname $0)/tfw_lib.sh"

# We should setup network queues for all existing network interfaces
# to prevent socket CPU migration, which leads to response reordering
# and broken HTTP1. Some network interfaces have some strange suffix
# like @if14, and we should remove it from device name.
declare devs=$(ip addr show up | grep -P '^[0-9]+' \
	       | awk '{ sub(/:/, "", $2); split($2,a,"@"); print a[1] }')

echo Enabling RSS on netwroking devices
tfw_set_net_queues "$devs"
