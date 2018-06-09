#!/bin/bash
#
# Tempesta FW service script.
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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

if [ "${TEMPESTA_LCK}" != "$0" ]; then
	env TEMPESTA_LCK="$0" flock -n -E 254 "/tmp/tempesta-lock-file" "$0" "$@"
	if [ $? -eq 254 ]; then
		echo "Cannot operate with Tempesta FW: locked by another process"
		exit 3
	fi
	exit
fi

. "$(dirname $0)/tfw_lib.sh"

script_path="$(dirname $0)"
tdb_path=${TDB_PATH:="$TFW_ROOT/tempesta_db/core"}
tfw_path=${TFW_PATH:="$TFW_ROOT/tempesta_fw"}
tls_path=${TLS_PATH:="$TFW_ROOT/tls"}
lib_path=${LIB_PATH:="$TFW_ROOT/lib"}
tfw_cfg_path=${TFW_CFG_PATH:="$TFW_ROOT/etc/tempesta_fw.conf"}

lib_mod=tempesta_lib
tls_mod=tempesta_tls
tdb_mod=tempesta_db
tfw_mod=tempesta_fw
declare -r LONG_OPTS="help,load,unload,start,stop,restart,reload"

declare devs=$(ip addr show up | awk '/^[0-9]+/ { sub(/:/, "", $2); print $2}')

usage()
{
	echo -e "\nUsage: ${TFW_NAME} [options] {action}\n"
	echo -e "Options:"
	echo -e "  -d <devs>   Ingress and egress network devices"
	echo -e "              (ex. -d \"lo ens3\").\n"
	echo -e "Actions:"
	echo -e "  --help      Show this message and exit."
	echo -e "  --load      Load Tempesta modules."
	echo -e "  --unload    Unload Tempesta modules."
	echo -e "  --start     Load modules and start."
	echo -e "  --stop      Stop and unload modules."
	echo -e "  --restart   Restart.\n"
	echo -e "  --reload    Live reconfiguration.\n"
}

error()
{
	echo "ERROR: $1" >&1
	exit 1
}

# Tempesta requires kernel module loading, so we need root credentials.
[ `id -u` -ne 0 ] && error "Please, run the script as root"

load_one_module()
{
	if [ -z "$1" ]; then
		echo "$0: Empty argument";
		exit 255;
	fi

	MOD_PATH_NAME="$1"; shift;
	MOD_NAME="$(basename ${MOD_PATH_NAME%%.ko})";

	lsmod | grep -w "${MOD_NAME}" 2>&1 > /dev/null || {
		echo "Loading module ${MOD_NAME} $@";
		insmod "${MOD_PATH_NAME}" "$@";
	}
}

# The separate load_modules/unload_modules routines are used for unit testing.
load_modules()
{
	echo "Loading Tempesta kernel modules..."

	# Set verbose kernel logging,
	# so debug messages are shown on serial console as well.
	echo '8 7 1 7' > /proc/sys/kernel/printk

	load_one_module "$lib_path/$lib_mod.ko" ||
		error "cannot load tempesta library module"

	load_one_module "$tls_path/$tls_mod.ko" ||
		error "cannot load tempesta TLS module"

	load_one_module "$tdb_path/$tdb_mod.ko" ||
		error "cannot load tempesta database module"

	load_one_module "$tfw_path/$tfw_mod.ko" "tfw_cfg_path=$tfw_cfg_path" ||
		error "cannot load tempesta module"
}

unload_modules()
{
	echo "Un-loading Tempesta kernel modules..."

	rmmod $tfw_mod
	rmmod $tdb_mod
	rmmod $tls_mod
	rmmod $lib_mod
}

setup()
{
	tfw_set_net_queues "$devs"

	# Tempesta builds socket buffers by itself, don't cork TCP segments.
	sysctl -w net.ipv4.tcp_autocorking=0 >/dev/null
	# Sotfirqs are doing more work, so increase input queues.
	sysctl -w net.core.netdev_max_backlog=10000 >/dev/null
	sysctl -w net.core.somaxconn=131072 >/dev/null
	sysctl -w net.ipv4.tcp_max_syn_backlog=131072 >/dev/null
}

# JS challenge file is a template file, update it using values defined in
# TempestaFW configuration file.
# Don't break start up process if there are errors in configuration file.
# Handling all the possible cases is too complicated for this script.
# Let TempestaFW warn user on issues.
update_js_challenge_template()
{
	if ! grep -q "^\s*js_challenge\s" $tfw_cfg_path; then
		return
	fi
	echo "...compile html templates"
	# Cache directive from start to end to simplify extracting values,
	# checking for line breaks, reordering of options and so on.
	js_dtv=`grep -m 1 -E '^\s*js_challenge\s[^;]+;' $tfw_cfg_path`
	c_dtv=`grep --m 1 -E '^\s*sticky\s[^;]+;' $tfw_cfg_path`

	d_min=`echo $js_dtv | perl -ne 'print "$1\n" if /\sdelay_min=(\d+)/'`
	d_range=`echo $js_dtv | perl -ne 'print "$1\n" if /\sdelay_range=(\d+)/'`
	template=`echo $js_dtv | perl -ne 'print "$1\n" if /(\/[^;\s]+)/'`
	cookie=`echo $c_dtv | perl -ne 'print "$1\n" if /\sname=\"?([\w_]+)\"?/'`

	# Set default values
	template=${template:-"/etc/tempesta/js_challenge.html"}
	cookie=${cookie:-"__tfw"}

	if [[ -z $d_min || -z $d_range ]]; then
		echo "Error: 'js_challenge' mandatory options not set!"
		return
	fi
	template=${template%%.html}".tpl"
	$script_path/update_template.pl $template $cookie $d_min $d_range
}

start()
{
	echo "Starting Tempesta..."

	TFW_STATE=$(sysctl net.tempesta.state 2> /dev/null)
	TFW_STATE=${TFW_STATE##* }

	[[ -z ${TFW_STATE} ]] && {
		setup;

		echo "...load Tempesta modules"
		load_modules;

		# Create database directory if it doesn't exist.
		mkdir -p /opt/tempesta/db/;
		# At this time we don't have stable TDB data format, so
		# it would be nice to clean all the tables before the start.
		# TODO: Remove the hack when TDB is fixed.
		rm -f /opt/tempesta/db/*.tdb;
	}

	update_js_challenge_template
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

reload()
{
	update_js_challenge_template
	echo "Running live reconfiguration of Tempesta..."
	sysctl -w net.tempesta.state=start >/dev/null
	if [ $? -ne 0 ]; then
		error "cannot reconfigure Tempesta FW"
	else
		echo "done"
	fi
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
		--reload)
			reload
			exit
			;;
		# Ignore any options after action.
		-d)
			devs=$2
			shift 2
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
