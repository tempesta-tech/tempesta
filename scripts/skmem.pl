#!/usr/bin/perl
#
# Copyright (C) 2021 Tempesta Technologies, Inc.
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

my ($rmem, $rcv_buf, $wmem, $snd_buf, $fwd_alloc) = (0, 0, 0, 0, 0);
my ($wmem_q, $ropt_mem, $back_log, $sock_drop) = (0, 0, 0, 0);

# See linux/net/ipv4/inet_diag.c for the fields reporting.
my @ss = `ss -tm '( dport = :https or sport = :https )' | grep skmem`;
foreach (@ss) {
	/\s+skmem:\(r(\d+),rb(\d+),t(\d+),tb(\d+),f(\d+),w(\d+),o(\d+),bl(\d+),
	 d(\d+)\)/x;

	$rmem += $1;
	$rcv_buf += $2;
	$wmem += $3;
	$snd_buf += $4;
	$fwd_alloc += $5;
	$wmem_q += $6;
	$ropt_mem += $7;
	$back_log += $8;
	$sock_drop += $9;
}

my $mem_free = `grep 'MemFree' /proc/meminfo`;
$mem_free =~ /MemFree:\s+(\d+)/;
$mem_free = $1;

print "mem_free:                $mem_free kB\n";
print "rmem_alloc:              $rmem\n";
print "wmem_alloc:              $wmem\n";
print "wmem_queued:             $wmem_q\n";
print "fwd_alloc:               $fwd_alloc\n";
print "opt_mem:                 $ropt_mem\n";
print "backlog_mem:             $back_log\n";
print "rcv_buf:                 $rcv_buf\n";
print "snd_buf:                 $snd_buf\n";
print "sock_drop:               $sock_drop\n";

