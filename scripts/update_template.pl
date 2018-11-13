#!/usr/bin/env perl
#
# Copyright (C) 2017-2018 Tempesta Technologies, Inc.
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
use File::Basename;
use POSIX;
use Template;
use Cwd 'abs_path';

my ($template, $sticky_name, $delay_min, $delay_range) = @ARGV;
if (!$template || $template !~ '.tpl$' || !$sticky_name
    || !$delay_min || !$delay_range)
{
	die "bad args!\n"
}

# Assemble HTML templates and minify resulting files.
sub assemble
{
	my ($src) = @_;
	my $dir = dirname($src);
	$src = basename($src);
	(my $dest = $src) =~ s/.tpl$/.html/;
	my $t = Template->new({
		INCLUDE_PATH	=> "$dir",
		OUTPUT_PATH	=> "$dir",
	});

	say "assemble template $src -> $dest";

	my $html;
	my $t_vals = {
		STICKY_NAME => $sticky_name,
		DELAY_MIN => $delay_min,
		DELAY_RANGE => $delay_range
	};
	$t->process($src, $t_vals, $dest)
		|| die $t->error(), "\n";
}

assemble(abs_path($template));

__END__

=head1	NAME

JavaScript Challenge template compilation tool for TempestaFW.

=head1	SYNOPSIS

./update_template.pl FILE COOKIE MIN_TIME RANGE_TIME

FILE		- Path template file from 'js_challenge' directive.
		  File extension must be '.tpl'.

COOKIE		- Tempesta FW sticky cookie name (directive 'js_challenge').

MIN_TIME	- Value of 'delay_min' parameter for directive 'js_challenge'.

RANGE_TIME	- Value of 'delay_range' parameter for directive
		  'js_challenge'.

=cut
