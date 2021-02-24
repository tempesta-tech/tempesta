#!/usr/bin/env perl
#
# Copyright (C) 2020-2021 Tempesta Technologies, Inc.
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
use 5.16.0;
use strict;
use warnings;

`modprobe msr`;

sub test {
    print "'$_[0]' bit: ",
    (hex(`rdmsr $_[1]`) & (1 << $_[2]) ? "" : "NOT "), "found\n";
}

test 'Activate secondary controls', 0x482, 63;
test 'Virtualize APIC accesses', 0x48b, 32;
test 'APIC-register virtualization', 0x48b, 40;
test 'Virtual-interrupt delivery', 0x48b, 41;

print "'Process posted interrupts' bit: ",
    (((hex(`rdmsr 0x480`) & (1 << 55))
      && (hex(`rdmsr 0x48d`) & (1 << 39)))
     || (hex(`rdmsr 0x481`) & (1 << 39)))
    ? "" : "NOT ", "found\n";
