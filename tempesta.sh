#!/bin/bash
#
# Tempesta FW service script.
#
# Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015 Tempesta Technologies, Inc.

root=$(dirname "$0")

# Resolve root to absolute path which is handy for kernel.
# pwd is used instead of readlink to avoid symlink resolution.
pushd "$root" > /dev/null
root="$(pwd)"
popd > /dev/null

arg=${1:-}
tdb_path=${TDB_PATH:="$root/tempesta_db/core"}
tfw_path=${TFW_PATH:="$root/tempesta_fw"}
tfw_cfg_path=${TFW_CFG_PATH:="$root/etc/tempesta_fw.conf"}
sched_ko_files=($(ls $tfw_path/sched/*.ko))

tdb_mod=tempesta_db
tfw_mod=tempesta_fw
tfw_sched_mod=tfw_sched_$sched

error()
{
	echo "ERROR: $1" >&1
	exit 1
}

# Tempesta requires kernel module loading, so we need root credentials.
[ `id -u` -ne 0 ] && error "Please, run the script as root"

# The separate load_modules/unload_modules routines are used for unit testing.
load_modules()
{
	echo "Loading Tempesta kernel modules..."

	# Set verbose kernel logging,
	# so debug messages are shown on serial console as well.
	echo '8 7 1 7' > /proc/sys/kernel/printk

	insmod $tdb_path/$tdb_mod.ko
	[ $? -ne 0 ] && error "cannot load tempesta database module"

	insmod $tfw_path/$tfw_mod.ko tfw_cfg_path=$tfw_cfg_path
	[ $? -ne 0 ] && error "cannot load tempesta module"

	for ko_file in "${sched_ko_files[@]}"
	do
		insmod $ko_file
		[ $? -ne 0 ] && error "cannot load tempesta scheduler module"
	done
}

start()
{
	echo "Starting Tempesta..."

	sysctl -w net.tempesta.state=start
	[ $? -ne 0 ] && error "cannot start Tempesta FW"

	echo "done"
}

stop()
{
	echo "Stopping Tempesta..."

	sysctl -w net.tempesta.state=stop
}

unload_modules()
{
	echo "Un-loading Tempesta kernel modules..."

	for ko_file in "${sched_ko_files[@]}"
	do
		mod_name = $(basename "${ko_file%.ko}") 
		rmmod $mod_name
	done
	
	rmmod $tfw_mod
	rmmod $tdb_mod
}

# Linux service interface.
case "$arg" in
	load_modules)
		load_modules
		;;
	unload_modules)
		unload_modules
		;;
	start)
		load_modules
		start
		;;
	stop)
		stop
		unload_modules
		;;
	restart)
		stop
		start
		;;
	*)
		echo "Usage: $0 {start|stop|restart}" >&1
		exit 2
		;;
esac

echo "done"
