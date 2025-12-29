#!/bin/bash
#
# Tempesta FW service script.
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2024 Tempesta Technologies, Inc.
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

if [ -z "$TFW_SYSTEMD" ]; then
	if [ "${TEMPESTA_LCK}" != "$0" ]; then
		env TEMPESTA_LCK="$0" flock -n -E 254 "/tmp/tempesta-lock-file" "$0" "$@"
		ret=$?
		if [ $ret -eq 254 ]; then
			echo "Cannot operate with Tempesta FW: locked by another process"
			exit 3
		fi
		exit $ret
	fi
fi

. "$(dirname $0)/tfw_lib.sh"

script_path="$(dirname $0)"
tdb_path=${TDB_PATH:="$TFW_ROOT/db/core"}
tfw_path=${TFW_PATH:="$TFW_ROOT/fw"}
tls_path=${TLS_PATH:="$TFW_ROOT/tls"}
lib_path=${LIB_PATH:="$TFW_ROOT/lib"}
utils_path=${UTILS_PATH:="$TFW_ROOT/utils"}
tfw_cfg_path=${TFW_CFG_PATH:="$TFW_ROOT/etc/tempesta_fw.conf"}
tfw_cfg_temp=${TFW_CFG_TMPL:="$TFW_ROOT/etc/tempesta_tmp.conf"}

tfw_logger_should_start=0
tfw_logger_pid_path="/var/run/tfw_logger.pid"
tfw_logger_timeout=3
mmap_host=""
mmap_log=""
mmap_user=""
mmap_password=""

lib_mod=tempesta_lib
tls_mod=tempesta_tls
tdb_mod=tempesta_db
tfw_mod=tempesta_fw
declare -r LONG_OPTS="help,load,unload,start,stop,restart,reload"
# We should setup network queues for all existing network interfaces
# to prevent socket CPU migration, which leads to response reordering
# and broken HTTP1. Some network interfaces have some strange suffix
# like @if14, and we should remove it from device name.
declare devs=$(ip addr show up | grep -P '^[0-9]+' \
	       | awk '{ sub(/:/, "", $2); split($2,a,"@"); print a[1] }')

usage()
{
	echo -e "\nUsage: ${TFW_NAME} {action}\n"
	echo -e "Actions:"
	echo -e "  --help               Show this message and exit."
	echo -e "  --load               Load Tempesta modules."
	echo -e "  --unload             Unload Tempesta modules."
	echo -e "  --start [options]    Load modules and start."
	echo -e "  --stop               Stop and unload modules."
	echo -e "  --restart [options]  Restart."
	echo -e "  --reload  [options]  Live reconfiguration.\n"
	echo -e "Options:"
	echo -e "  -d \"<devs>\"          Ingress and egress network devices, also may be set with TFW_DEV, but the option has more priority."
	echo -e "                       Multiple device sequence should be surrounded by quotes for correct processing."
	echo -e "                       (ex. --start -d \"lo ens3\").\n"
}

get_opts()
{
	echo "$1" | grep -E "^\s*$2\b" | sed -E "s/$2 //; s/;$//"
}

get_opt_value()
{
	echo "$1" | grep -oE "$2=[^ ;]+" | sed "s/$2=//"
}

opt_exists()
{
	echo "$1" | grep -q "\b$2\b" && return 1 || return 0
}

remove_opts_by_mask()
{
	echo "$1" | sed -E "s/\b$2[^ ;]+ ?//g"
}

templater()
{
	cfg_content=""
	# Replace !include dircetive with file contents
	> $tfw_cfg_temp
	mkdir $TFW_ROOT/etc 2>/dev/null
	while IFS= read -r raw_line
	do
		line=$(echo "$raw_line" | sed -e '/request /s/\\r\\n/\x0d\x0a/g')
		if [[ ${line:0:1} = \# ]]; then
			:
		elif [[ $line =~ '!include' ]]; then
			IFS=' '
			read -ra path <<< "$line"

			files=$(find ${path[1]} -type f -regextype posix-extended -regex '.*\.conf$')
			while IFS= read -r file; do
				inc_file=$(cat $file \
					| sed -e '/request /s/\\r\\n/\x0d\x0a/g')

				cfg_content+="$inc_file"$'\n'
			done <<< "$files"
		else
			cfg_content+="$line"$'\n'
		fi
	done < "$tfw_cfg_path"

	opts=$(get_opts "$cfg_content" "access_log")
	while read -r line; do
		if [ $(opt_exists "$line" "mmap"; echo $?) -ne 0 ]; then
			tfw_logger_should_start=1
			mmap_log=$(get_opt_value "$line" "mmap_log")
			mmap_host=$(get_opt_value "$line" "mmap_host")
			mmap_user=$(get_opt_value "$line" "mmap_user")
			mmap_password=$(get_opt_value "$line" "mmap_password")

			[[ -n "$mmap_log" && -n "$mmap_host" ]] ||
				error "if mmaps enabled in access log, there have to be mmap_host and mmap_log options"
		fi
	done <<< "$opts"

	cfg_content=$(remove_opts_by_mask "$cfg_content" "mmap_")

	echo "$cfg_content" > $tfw_cfg_temp
}

remove_tmp_conf()
{
	if [ -f $tfw_cfg_temp ]; then
		rm $tfw_cfg_temp
	fi
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

	load_one_module "$tfw_path/$tfw_mod.ko" "tfw_cfg_path=$tfw_cfg_temp" ||
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

	# Enable sysrq
	echo 1 > /proc/sys/kernel/sysrq

	# Automatically immediately reboot on kernel crashes and ignore kernel warnings.
	echo 1 > /proc/sys/kernel/panic
	echo 1 > /proc/sys/kernel/panic_on_oops
	echo 0 > /proc/sys/kernel/panic_on_warn

	# Tempesta builds socket buffers by itself, don't cork TCP segments.
	sysctl -w net.ipv4.tcp_autocorking=0 >/dev/null
	# Sotfirqs are doing more work, so increase input queues.
	sysctl -w net.core.netdev_max_backlog=10000 >/dev/null
	sysctl -w net.core.somaxconn=131072 >/dev/null
	sysctl -w net.ipv4.tcp_max_syn_backlog=131072 >/dev/null

	# More aggressively recycle sockets in FIN-WAIT-1 and FIN-WAIT-2 states,
	# quite common for L7 DDoS.
	# See tcp_check_oom(), Documentation/networking/ip-sysctl.rst
	#
	# Do not shrink tcp_max_orphans and tcp_max_tw_buckets to not to get
	# spontaneous connection resets followed by reconnection storms.
	sysctl -w net.ipv4.tcp_orphan_retries=3 >/dev/null # timeout for 8s
	# The minimum number of retries, recommended by RFC 1122.
	sysctl -w net.ipv4.tcp_retries2=8 >/dev/null
	sysctl -w net.ipv4.tcp_fin_timeout=10 >/dev/null

	# Increase the total TCP memory to mitigate
	# "TCP: out of memory -- consider tuning tcp_mem" problem.
	# This increases the total TCP memory, but leave per-socket limits as
	# defaults to not allow too memory hungry sockets.
	#
	# Linux sets the sysctl in tcp_init_mem() as ~5%, ~6% and ~9% of
	# (all_pages - pages_beyond_high_watermark). We're set tcp_mem as
	# 10%, 20% and 40% of available memory. 40% is a lot having that we
	# need memmory for cache, to handle HTTP requests and responses and so
	# on, so use 2 lower pressure limit.
	# We can neglect high watermark pages, which are hard to compute.
	# Leave per-socket limits to get more connections, not heavier connections.
	local new_tcp_mem
	new_tcp_mem=$(perl -ne '/^MemTotal:\s+(\d+)/ and
				print join(" ", map { int($1 / 4 * $_) } .1, .2, .4)
			       ' /proc/meminfo)
	sysctl -w net.ipv4.tcp_mem="$new_tcp_mem" >/dev/null
}

update_single_js_template()
{
	js_line=`echo $1 | perl -ne 'print "$1\n" if /js_challenge\s+([^;]*);/'`

	if [[ -z $js_line ]]; then
		return
	fi

	template=`echo $js_line | perl -ne 'print "$1\n" if /([^\s]+.html)/'`
	d_min=`echo $1 | perl -ne 'print "$1\n" if /\sdelay_min=(\d+)/'`
	d_range=`echo $1 | perl -ne 'print "$1\n" if /\sdelay_range=(\d+)/'`
	cookie=`echo $1 | perl -ne 'print "$1\n" if /\sname=\"?([\w_]+)\"?/'`

	# Set default values
	template=${template:-"/etc/tempesta/js_challenge.html"}
	cookie=${cookie:-"__tfw"}

	if [[ -z $d_min || -z $d_range ]]; then
		error "at line 'js_challenge $js_line': mandatory options 'delay_min' or 'delay_range' not set!"
	fi
	template=${template%%.html}".tpl"
	$script_path/update_template.pl $template $cookie $d_min $d_range
	if [ $? -ne 0 ]; then
		error "at line 'js_challenge $js_line': tempate file can't be prepared"
	fi
}

# JS challenge file is a template file, update it using values defined in
# TempestaFW configuration file.
# Don't break start up process if there are errors in configuration file.
# Handling all the possible cases is too complicated for this script.
# Let TempestaFW warn user on issues.
update_js_challenge_templates()
{
	templater

	echo "...compile html templates for JS challenge"
	# Just a simple parser: don't care about commented brackets and sections.
	# More sophisticated parser should work inside configuration processing.
	# Since the whole configuration subsystem is to be redesigned, this
	# simple approach is going to be suffitient for now.
	cat $tfw_cfg_path | tr -d '\n' | grep -oP 'sticky\s+{\K[^}]+' | while read -r line ; do
		update_single_js_template "$line"
	done
}

prepare_db_directory()
{
	# Create database directory if it doesn't exist.
	mkdir -p /opt/tempesta/db/;
	# At this time we don't have stable TDB data format, so
	# it would be nice to clean all the tables before the start.
	# TODO #515: Remove the hack when TDB is fixed.
	rm -f /opt/tempesta/db/*.tdb;
}

start_tempesta_and_check_state()
{
	local _err

	_err=$((echo start > /proc/sys/net/tempesta/state) 2>&1)
	TFW_STATE=$(sysctl net.tempesta.state 2> /dev/null)
	TFW_STATE=${TFW_STATE##net.tempesta.state = }

	remove_tmp_conf
	if [[ ${TFW_STATE} != "start" && ${TFW_STATE} != "start (failed reconfig)" ]]; then
		unload_modules
		error "cannot start Tempesta FW (sysctl message: ${_err##*: }, please check dmesg)"
	else
		if [[ $TFW_STATE == "start (failed reconfig)" ]]; then
			error "Tempesta FW reconfiguration fails (sysctl message: ${_err##*: }, please check dmesg)."`
				`" Tempesta FW is still running with old configuration."
		fi
	fi
}

start_tfw_logger()
{
	if [ $tfw_logger_should_start -eq 0 ]; then
		return
	fi

	if [ -z "$mmap_host" ] || [ -z "$mmap_log" ]; then
		error "You need to specify 'mmap_host' and 'mmap_log' "`
		      `"if access_log mmap was specified"
		return
	fi

	"$utils_path/tfw_logger" -H "$mmap_host" -l "$mmap_log" -u "$mmap_user" -p "$mmap_password" ||
		error "cannot start tfw_logger daemon"

	start_time=$(date +%s)
	while [[ ! -f "$tfw_logger_pid_path" ]]; do
		current_time=$(date +%s)
		elapsed_time=$((current_time - start_time))

		if (( elapsed_time >= tfw_logger_timeout )); then
			sysctl -e -w net.tempesta.state=stop
			unload_modules
			tfw_irqbalance_revert
			error "tfw_logger failed to start, see $mmap_log for details"
		fi

		sleep 0.1
	done

}

stop_tfw_logger()
{
	if [ -e $tfw_logger_pid_path ]; then
		"$utils_path/tfw_logger" -s
	fi
}

start()
{
	echo "Starting Tempesta..."

	TFW_STATE=$(sysctl net.tempesta.state 2> /dev/null)
	TFW_STATE=${TFW_STATE##* }
	TFW_LOGGER_EXEC=$(expr "$TFW_STATE" != "start")

	if [[ -z ${TFW_STATE} ]]; then
		setup

		echo "...load Tempesta modules"
		load_modules;

		prepare_db_directory;
	elif [[ ${TFW_STATE} == "stop" ]]; then
		prepare_db_directory;
	fi

	update_js_challenge_templates
	if [ $? -ne 0 ]; then
		unload_modules
		error "cannot start Tempesta FW: error at configuration pre-processing"
	fi
	echo "...start Tempesta FW"

	start_tempesta_and_check_state

	if [[ $TFW_LOGGER_EXEC == 1 ]]; then
		start_tfw_logger
	fi

	echo "done"
}

stop()
{
	echo "Stopping Tempesta..."

	stop_tfw_logger

	sysctl -e -w net.tempesta.state=stop

	echo "...unload Tempesta modules"
	unload_modules

	tfw_irqbalance_revert

	echo "done"
}

reload()
{
	update_js_challenge_templates
	echo "Running live reconfiguration of Tempesta..."

	start_tempesta_and_check_state
	echo "done"
}

# function to validate networking devices (-d option) that may be provided from command line arguments and via env var
# for the function, $1 is expected as `-d` key and $2 is expected as sequence of devices
# for example, if --start with -d "<devices>" (list of devices to configure)
validate_net_devices()
{
	if [ -n "$1" ] && [ "$1" == "-d" ] && [ -n "$2" ]; then
		if [ -n "$TFW_DEV" ]; then
			echo You are trying to set networking devices with TFW_DEV and command argument, using command argument value \'"$2"\'
		else
			echo Using only networking devices from command line argument: \'"$2"\'
		fi
		devs=$2
	elif [ -n "$TFW_DEV" ]; then
		echo Using only networking devices from TFW_DEV: \'"$TFW_DEV"\'
		devs=$TFW_DEV
	fi
}

# validate number of options for arguments that do not accept extra options to notify an user
validate_num_of_opt()
{
	fact_n="$#"
	action="$1"
	shift
	if [ "$fact_n" -gt 2 ]; then
		echo Command: \'"$action"\' has no options, all excessive arguments \'"$*"\' will be ignored.
	fi
}

args=$(getopt -o "d:" -a -l "$LONG_OPTS" -- "$@")
eval set -- "${args}"
while :; do
	case "$1" in
		# Selectors for internal usage.
		--load)
			validate_num_of_opt "$@"
			load_modules
			exit
			;;
		--unload)
			validate_num_of_opt "$@"
			unload_modules
			exit
			;;
		# User CLI.
		--start)
			validate_net_devices "$2" "$3"
			start
			exit
			;;
		--stop)
			validate_num_of_opt "$@"
			stop
			exit
			;;
		--restart)
			validate_net_devices "$2" "$3"
			stop
			start
			exit
			;;
		--reload)
			validate_net_devices "$2" "$3"
			reload
			exit
			;;
		--help)
			usage
			exit
			;;
		*)
			error "Bad command line argument: $1, check '--help' for details."
			exit 2
			;;
	esac
done
