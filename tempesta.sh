#!/bin/bash
#
# Tempesta FW service script.
#
# 2012-2014. Written by NatSys Lab. (info@natsys-lab.com).

SSOCKET=sync_socket
TDB=tempesta_db
TFW=tempesta_fw
TFW_ROOT=`pwd`/$TFW
TFW_CACHE_SIZE=`expr 256 \* 1024`
TFW_CACHE_PATH=$TFW_ROOT/cache

arg=${1:-}
ss_path=${SYNC_SOCKET:="./"}
tdb_path=${TDB:="./"}
sched=${SCHED:="dummy"}

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

	mkdir -p $TFW_CACHE_PATH 2>/dev/null

	insmod $ss_path/$SSOCKET.ko
	[ $? -ne 0 ] && error "cannot load synchronous sockets module"

	insmod $tdb_path/$TDB.ko
	[ $? -ne 0 ] && error "cannot load tempesta database module"

	insmod $TFW_ROOT/$TFW.ko cache_size=$TFW_CACHE_SIZE \
				 cache_path="$TFW_CACHE_PATH"
	[ $? -ne 0 ] && error "cannot load tempesta module"

	insmod $TFW_ROOT/sched/tfw_sched_${sched}.ko
	[ $? -ne 0 ] && error "cannot load scheduler module"

	sysctl --load=tempesta.sysctl.conf
	[ $? -ne 0 ] && error "cannot apply configuration via sysctl"

	echo "done"
}

stop()
{
	echo "Stopping Tempesta"

	rmmod $TFW
	rmmod $TDB
	rmmod $SSOCKET

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
