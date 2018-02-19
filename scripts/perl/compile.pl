#!/usr/bin/env perl
#
# Tempesta-Tech.com Web site compilation tool.
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
use CSS::Minifier::XS;
use File::Basename;
use JavaScript::Minifier::XS;
use POSIX;
use Template;
use Cwd 'abs_path';


use lib dirname($0); # lookup Packer in current directory
use Packer;

my ($tfw_cfg_dir, $sticky_name, $delay_min, $delay_range) = @ARGV;

sub minify
{
	my ($suff, $orig, $minifier) = @_;

	(my $dest = $orig) =~ s/.$suff.tpl$/.$suff/;

	say "minify: $orig -> $dest";

	open(INFILE, $orig) or die "Error reading file: $!";
	local $/ = undef;
	my $in = <INFILE>;
	close INFILE;

	my $min = $minifier->($in);
	open(OUTFILE, ">", $dest) or die "Error writing file: $!";
	print { *OUTFILE } $min;
	close OUTFILE;
}

# Assemble HTML templates and minify resulting files.
sub assemble
{
	my ($src) = @_;
	(my $dest = $src) =~ s/.tpl$/.html/;
	my $t = Template->new({
		INCLUDE_PATH	=> "$tfw_cfg_dir",
		OUTPUT_PATH	=> ".",
		ABSOLUTE	 => 1,
	});

	say "assemble template $src -> $dest";

	my $html;
	my $t_vals = {
		STICKY_NAME => $sticky_name,
		DELAY_MIN => $delay_min,
		DELAY_RANGE => $delay_range
	};
	$t->process($src, $t_vals, \$html)
		|| die $t->error(), "\n";

	my $min = Packer::minify(\$html, {
		remove_comments		=> 1,
		remove_newlines		=> 1,
		no_compress_comment	=> 1,
		html5			=> 1,
	});
	open(OUTFILE, ">", $dest) or die "Error writing file: $!";
	print { *OUTFILE } $min;
	close OUTFILE;
}

my @css = glob($tfw_cfg_dir . '/css/*.tpl');
minify("css", $_, \&CSS::Minifier::XS::minify) foreach (@css);
my @js = glob($tfw_cfg_dir . '/js/*.tpl');
minify("js", $_, \&JavaScript::Minifier::XS::minify) foreach (@js);
my @tpl = glob($tfw_cfg_dir . '/*.tpl');
assemble($_) foreach (@tpl);


__END__

=head1	NAME

Web site static templates compilation and optimization tool.
Now minification for HTML, JS, CSS files only is implemented.

=head1	SYNOPSIS

./compile.pl

=head1

At some point optimization part of the tool must be replaced by Tempesta FW
optimization daemon, see https://github.com/tempesta-tech/tempesta/issues/528
for details. Other possible optimization can be introduced, e.g.:

* https://developers.google.com/closure/compiler/

* pictures compression (OptiPNG, giflossy, mozjpeg, convert, WebP etc.)

The Perl minification packages are outdated. It seems Gulp (https://gulpjs.com/)
is a much better choice for the project compilation. However, JS is even uglier
than Perl, so SSJS is an evil and isn't appreciated in the project.

=cut
