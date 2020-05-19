#!/bin/bash
#
# Copyright (C) 2020 Tempesta Technologies, Inc.
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

# Order of the tests is important:
# 1. MPI math must run first as the most basic;
# 2. MPI test runs after MPI math, but before any crypto algorithms;
# 3. elliptic curves test is the base for ECDH and ECDSA, so run it now;
# 4. after that we can run all the tests for crypto lagorithms.
TESTS=( mpi_math mpi ec_p256 ec_p384 ec_25519 ecdsa_p256 ecdh_p256 rsa)

for t in "${TESTS[@]}"; do
	echo -e "\nrun [$t] test: "
	$root/test_$t
done
