#!/usr/bin/env perl
#
# Copyright (C) 2020-2022 Tempesta Technologies, Inc.
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
require File::Temp;
use File::Temp ();

`modprobe msr`;

sub rtrim { my $s = shift; $s =~ s/\s+$//; return $s };

sub test {
    print "'$_[0]' bit: ",
    (hex(rtrim(`rdmsr $_[1]`)) & (1 << $_[2]) ? "" : "NOT "), "found\n";
}

sub adx_test {
    my $adx_test_src = q|#include <stdio.h>
int main() {
  unsigned long long op1 = 0x1100110022002200;
  unsigned long long op2 = 0x00ff11ee22dd33cc;
  __asm__ __volatile__("adcx %%rbx,%%rax" : "=a"(op1) : "a"(op1), "b"(op2));
  printf("%s\n", "ADX supported");
}|;
    my $tmp_src = File::Temp->new(SUFFIX => '.c');
    print $tmp_src $adx_test_src;
    my $tmp_exe_filename = $tmp_src->filename;
    $tmp_exe_filename =~ s{\.[^.]*(?:\.c)?$}{};
    my $exit_status = system("gcc", $tmp_src->filename, "-o", $tmp_exe_filename);
    my $test_output = `$tmp_exe_filename`;
    print "'Intel ADX Instruction Extensions' support: ",
        index($test_output, "ADX supported") == -1 || $exit_status != 0 ?
        "NOT " : "", "found\n";
    if ($exit_status != 0) {
        return;
    }
    unlink($tmp_exe_filename);
}

test 'Activate secondary controls', 0x482, 63;
test 'Virtualize APIC accesses', 0x48b, 32;
test 'APIC-register virtualization', 0x48b, 40;
test 'Virtual-interrupt delivery', 0x48b, 41;

print "'Process posted interrupts' bit: ",
    (((hex(rtrim(`rdmsr 0x480`)) & (1 << 55))
      && (hex(rtrim(`rdmsr 0x48d`)) & (1 << 39)))
     || (hex(rtrim(`rdmsr 0x481`)) & (1 << 39)))
    ? "" : "NOT ", "found\n";

adx_test;
