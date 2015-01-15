#!/bin/bash
#
# Tempesta FW service script.
#
# Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015 Tempesta Technologies.

root=$(dirname "$0")

arg=${1:-}
ss_path=${SS_PATH:="$root/sync_socket"}
tdb_path=${TDB_PATH:="$root/tempesta_db"}
tfw_path=${TFW_PATH:="$root/tempesta_fw"}
tfw_cfg_path=${TFW_CFG_PATH:="$root/tempesta_fw.conf"}
sched=${SCHED:="dummy"}

ss_mod=sync_socket
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

start()
{
	echo "Starting Tempesta..."

	# Set verbose kernel logging,
	# so debug messages are shown on serial console as well.
	echo '8 7 1 7' > /proc/sys/kernel/printk

	insmod $ss_path/$ss_mod.ko
	[ $? -ne 0 ] && error "cannot load synchronous sockets module"

	insmod $tdb_path/$tdb_mod.ko
	[ $? -ne 0 ] && error "cannot load tempesta database module"

	insmod $tfw_path/$tfw_mod.ko tfw_cfg_path=$tfw_cfg_path
	[ $? -ne 0 ] && error "cannot load tempesta module"

	insmod $tfw_path/sched/tfw_sched_${sched}.ko
	[ $? -ne 0 ] && error "cannot load tempesta scheduler module"

	sysctl -w net.tempesta.state=start
	[ $? -ne 0 ] && error "cannot start Tempesta FW"

	echo "done"
}

stop()
{
	echo "Stopping Tempesta"
	
	sysctl -w net.tempesta.state=stop

	rmmod tfw_sched_mod
	rmmod tfw_mod
	rmmod tdb_mod
	rmmod ss_mod

	echo "done"
}

# Linux service interface.
case "$arg" in
	start)
		start
		;;
	stop)
		stop
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
