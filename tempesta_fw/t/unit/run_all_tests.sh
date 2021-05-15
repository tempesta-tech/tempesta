#!/bin/bash
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2021 Tempesta Technologies, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

root=$(dirname "$0")
name=`basename $0` # program name (comm name in ps)

# Resolve root to absolute path which is handy for kernel.
# pwd is used instead of readlink to avoid symlink resolution.
pushd "$root" > /dev/null
root="$(pwd)"
popd > /dev/null

clean_exit()
{
	rmmod tfw_test 2>/dev/null
	rmmod tfw_fuzzer 2>/dev/null
	rmmod tempesta_db 2>/dev/null
	rmmod tempesta_lib 2>/dev/null

	[ ${1} -ne 0 ] && exit ${1}
}

echo -e "\n @@@ RUNNING UNIT TESTS..."

# Load helper modules - here we test and mock Tempesta FW module only,
# so that's OK to include all the service modules.
insmod $root/../../../lib/tempesta_lib.ko || clean_exit 1
insmod $root/../../../tempesta_db/core/tempesta_db.ko || clean_exit 1

insmod $root/../tfw_fuzzer.ko || clean_exit 1
insmod $root/tfw_test.ko || clean_exit 1

clean_exit 0

echo -e "\n @@@ UNIT TEST OUTPUT SUMMARY (see dmesg for full log):\n"
dmesg | grep tfw_test

`dmesg | grep tfw_test | tail -n 10 | grep -q "finish - all passed"`
res=$?
if [ "$res" != "0" ]
then
    echo "Tests failed!"
    exit 1
fi
