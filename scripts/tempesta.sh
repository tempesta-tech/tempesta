#!/bin/bash
#
# Tempesta FW service script.
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2016 Tempesta Technologies, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

. "$(dirname $0)/tfw_lib.sh"

tdb_path=${TDB_PATH:="$TFW_ROOT/tempesta_db/core"}
tfw_path=${TFW_PATH:="$TFW_ROOT/tempesta_fw"}
tls_path=${TLS_PATH:="$TFW_ROOT/tls"}
class_path="$tfw_path/classifier/"
tfw_cfg_path=${TFW_CFG_PATH:="$TFW_ROOT/etc/tempesta_fw.conf"}
sched_ko_files=($(ls $tfw_path/sched/*.ko))

tls_mod=tempesta_tls
tdb_mod=tempesta_db
tfw_mod=tempesta_fw
tfw_sched_mod=tfw_sched_$sched
frang_mod="tfw_frang"
declare frang_enable=
declare -r LONG_OPTS="help,load,unload,start,stop,restart"

declare devs=$(ip addr show up | awk '/^[0-9]+/ { sub(/:/, "", $2); print $2}')

usage()
{
	echo -e "\nUsage: ${TFW_NAME} [options] {action}\n"
	echo -e "Options:"
	echo -e "  -f          Load Frang, HTTP DoS protection module."
	echo -e "  -d <devs>   Ingress and egress network devices"
	echo -e "              (ex. -d \"lo ens3\").\n"
	echo -e "Actions:"
	echo -e "  --help      Show this message and exit."
	echo -e "  --load      Load Tempesta modules."
	echo -e "  --unload    Unload Tempesta modules."
	echo -e "  --start     Load modules and start."
	echo -e "  --stop      Stop and unload modules."
	echo -e "  --restart   Restart.\n"
}

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

	insmod $tls_path/$tls_mod.ko
	[ $? -ne 0 ] && error "cannot load tempesta TLS module"

	insmod $tdb_path/$tdb_mod.ko
	[ $? -ne 0 ] && error "cannot load tempesta database module"

	insmod $tfw_path/$tfw_mod.ko tfw_cfg_path=$tfw_cfg_path
	[ $? -ne 0 ] && error "cannot load tempesta module"

	for ko_file in "${sched_ko_files[@]}"; do
		insmod $ko_file
		[ $? -ne 0 ] && error "cannot load tempesta scheduler module"
	done

	if [ "$frang_enable" ]; then
		echo "Load Frang"
		insmod $class_path/$frang_mod.ko
		[ $? -ne 0 ] && error "cannot load $frang_mod module"
	fi
}

unload_modules()
{
	echo "Un-loading Tempesta kernel modules..."

	for ko_file in "${sched_ko_files[@]}"; do
		rmmod $(basename "${ko_file%.ko}")
	done

	[ "`lsmod | grep \"\<$frang_mod\>\"`" ] && rmmod $frang_mod
	rmmod $tfw_mod
	rmmod $tdb_mod
	rmmod $tls_mod
}

start()
{
	echo "Starting Tempesta..."

	tfw_set_net_queues "$devs"

	# Tempesta builds socket buffers by itself, don't cork TCP segments.
	sysctl -w net.ipv4.tcp_autocorking=0 >/dev/null
	# Sotfirqs are doing more work, so increase input queues.
	sysctl -w net.core.netdev_max_backlog=10000 >/dev/null
	sysctl -w net.core.somaxconn=131072 >/dev/null
	sysctl -w net.ipv4.tcp_max_syn_backlog=131072 >/dev/null

	echo "...load Tempesta modules"
	load_modules

	# Create database directory if it doesn't exist.
	mkdir -p /opt/tempesta/db/
	# At this time we don't have stable TDB data format, so
	# it would be nice to clean all the tables before the start.
	# TODO: Remove the hack when TDB is fixed.
	rm -f /opt/tempesta/db/*.tdb

	echo "...start Tempesta FW"
	sysctl -w net.tempesta.state=start >/dev/null
	if [ $? -ne 0 ]; then
		unload_modules
		error "cannot start Tempesta FW"
	else
		echo "done"
	fi
}

stop()
{
	echo "Stopping Tempesta..."

	sysctl -w net.tempesta.state=stop

	echo "...unload Tempesta modules"
	unload_modules

	echo "done"
}

args=$(getopt -o "d:f" -a -l "$LONG_OPTS" -- "$@")
eval set -- "${args}"
while :; do
	case "$1" in
		# Selectors for internal usage.
		--load)
			load_modules
			exit
			;;
		--unload)
			unload_modules
			exit
			;;
		# User CLI.
		--start)
			start
			exit
			;;
		--stop)
			stop
			exit
			;;
		--restart)
			stop
			start
			exit
			;;
		# Ignore any options after action.
		-d)
			devs=$2
			shift 2
			;;
		-f)
			frang_enable=1
			shift
			;;
		--help)
			usage
			exit
			;;
		*)
			error "Bad command line argument: $opt"
			exit 2
			;;
	esac
done
