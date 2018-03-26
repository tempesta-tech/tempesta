#!/bin/bash
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

echo -e "\n @@@ RUNNING UNIT TESTS..."
insmod $root/../tfw_fuzzer.ko
insmod $root/tfw_test.ko
rmmod tfw_test
rmmod tfw_fuzzer

echo -e "\n @@@ UNIT TEST OUTPUT SUMMARY (see dmesg for full log):\n"
dmesg | grep tfw_test

`dmesg | grep tfw_test | tail -n 10 | grep -q "finish - all passed"`
res=$?
if [ "$res" != "0" ]
then
    echo "Tests failed!"
    exit 1
fi
