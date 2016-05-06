#!/bin/bash
#
# Tempesta Bomber: a tool for HTTP servers stress testing.
#
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

# Path to testing modules.
tm_path=${TFW_PATH:="$TFW_ROOT/tempesta_fw/t"}

declare conn= iter= msgs= srv= thr= unload= verbose=

declare -r long_opts="help,start,stop"

usage()
{
	echo
	echo -e "Tempesta Bomber: a tool for HTTP servers stress testing"
	echo
	echo -e "The bomber runs T threads in I iterations. Each thread"
	echo -e "establishes C connections to the server in each iteration"
	echo -e "and sends M messages over each connection."
	echo
	echo -e "Usage: ${TFW_NAME} [options] {action}"
	echo
	echo -e "Options:"
	echo -e "  -a <addr>   Server address, \"127.0.0.1:80\" by default."
	echo -e "  -c <C>      Number of concurrent connections, 2 by default."
	echo -e "  -d <devs>   Ingress and egress network devices"
	echo -e "              (ex. -d \"lo ens3\").\n"
	echo -e "  -i <I>      Number of iterations, 2 by default."
	echo -e "  -m <M>      Number messages per connection, 2 by default."
	echo -e "  -t <T>      Number of client threads, 2 by default."
	echo -e "  -u          Unload Tempesta modules on stop action."
	echo -e "  -v          Verbose output."
	echo
	echo -e "Actions:"
	echo -e "  --help      Show this message and exit."
	echo -e "  --start     Start the bomber."
	echo -e "  --stop      Stop the bomber."
	echo
}

error()
{
	echo "ERROR: $1" >&1
	exit 1
}

stop()
{
	echo "Tempesta: stop and unload bomber..."

	rmmod tfw_bomber
	rmmod tfw_fuzzer
	[ "$unload" ] && $TFW_SCRIPTS/tempesta.sh --unload

	echo "done"
}

start()
{
	tfw_set_rps

	echo "Tempesta: bombing the server..."

	if [ -z "`lsmod | grep \"\<tempesta_fw\>\"`" ]; then
		$TFW_SCRIPTS/tempesta.sh --load
		[ $? -ne 0 ] && error "cannot load TFW environment"
	fi

	insmod $tm_path/tfw_fuzzer.ko
	[ $? -ne 0 ] && error "cannot load HTTP fuzzer"

	insmod $tm_path/tfw_bomber.ko $conn $iter $msgs $srv $thr $verbose
	[ $? -ne 0 ] && error "cannot start bomber"

	stop
}

args=$(getopt -o "a:c:d:i:m:t:uv" -a -l "$long_opts" -- "$@")
eval set -- "${args}"
while :; do
	case "$1" in
		--start)
			start
			exit
			;;
		--stop)
			stop
			exit
			;;
		# Ignore any options after action.
		-a)
			srv="s=\"$2\""
			shift 2
			;;
		-c)
			conn="c=$2"
			shift 2
			;;
		-d)
			TFW_DEVS=$2
			shift 2
			;;
		-i)
			iter="i=$2"
			shift 2
			;;
		-m)
			msgs="m=$2"
			shift 2
			;;
		-t)
			thr="t=$2"
			shift 2
			;;
		-u)
			unload=1
			shift
			;;
		-v)
			verbose="v=1"
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
