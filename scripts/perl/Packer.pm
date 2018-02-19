package Packer;

use 5.008009;
use strict;
use warnings;
use Carp;
use RegGrp;

# -----------------------------------------------------------------------------

our $VERSION = '2.05';

our @BOOLEAN_ACCESSORS = (
    'remove_comments',
    'remove_newlines',
    'no_compress_comment',
    'html5',
);

our @JAVASCRIPT_OPTS    = ( 'clean', 'obfuscate', 'shrink', 'best' );
our @CSS_OPTS           = ( 'minify', 'pretty' );

our $REQUIRED_JAVASCRIPT_PACKER = '1.002001';
our $REQUIRED_CSS_PACKER        = '1.000001';

our @SAVE_SPACE_ELEMENTS = (
    'a', 'abbr', 'acronym', 'address', 'b', 'bdo', 'big', 'button', 'cite',
    'del', 'dfn', 'em', 'font', 'i', 'input', 'ins', 'kbd', 'label', 'q',
    's', 'samp', 'select', 'small', 'strike', 'strong', 'sub', 'sup', 'u', 'var'
);

our @VOID_ELEMENTS = (
    'area', 'base', 'br', 'col', 'command', 'embed', 'hr', 'img', 'input',
    'keygen', 'link', 'meta', 'param', 'source', 'track', 'wbr'
);

# Some regular expressions are from HTML::Clean

our $COMMENT        = '((?>\s*))(<!--(?:(?![#\[]| google_ad_section_).*?)?-->)((?>\s*))';

our $PACKER_COMMENT = '<!--\s*HTML::Packer\s*(\w+)\s*-->';

our $DOCTYPE        = '<\!DOCTYPE[^>]*>';

our $DONT_CLEAN     = '(<\s*(pre|code|textarea|script|style)[^>]*>)(.*?)(<\s*\/\2[^>]*>)';

our $WHITESPACES    = [
    {
        regexp      => qr/^\s*/s,
        replacement => ''
    },
    {
        regexp      => qr/\s*$/s,
        replacement => ''
    },
    {
        regexp      => '^\s*',
        replacement => '',
        modifier    => 'm'
    },
    {
        regexp      => '[^\S\n]*$',
        replacement => '',
        modifier    => 'm'
    },
    {
        regexp      => qr/(?<=>)[^<>]*(?=<)/sm,
        replacement => sub {
            my $match = $_[0]->{match};

            $match =~ s/[^\S\n]{2,}/ /sg;
            $match =~ s/\s*\n+\s*/\n/sg;

            return $match;
        }
    },
    {
        regexp      => '<\s*(\/)?\s*',
        replacement => sub {
            return sprintf( '<%s', $_[0]->{submatches}->[0] );
        },
        modifier    => 's'
    },
    {
        regexp      => '\s*(\/)?\s*>',
        replacement => sub {
            return sprintf( '%s>', $_[0]->{submatches}->[0] );
        },
        modifier    => 's'
    }
];

our $NEWLINES_TAGS = [
    {
        regexp      => '(\s*)(<\s*\/?\s*(?:' . join( '|', @SAVE_SPACE_ELEMENTS ) . ')\b[^>]*>)(\s*)',
        replacement => sub {
            return sprintf( '%s%s%s', $_[0]->{submatches}->[0] ? ' ' : '', $_[0]->{submatches}->[1], $_[0]->{submatches}->[2] ? ' ' : '' );
        },
        modifier    => 'is'
    }
];

our $NEWLINES = [
    {
        regexp      => '(.)\n(.)',
        replacement => sub {
            my ( $pre, $post ) = @{$_[0]->{submatches}};

            my $ret;

            if ( $pre eq '>' and $post eq '<' ) {
                $ret = $pre . $post;
            }
            elsif ( $pre eq '-' and $post =~ /[\w]/ ) {
                $ret = $pre . $post;
            }
            else {
                $ret = $pre . ' ' . $post;
            }

            return $ret;
        }
    }
];

our @REGGRPS        = ( 'newlines', 'newlines_tags', 'whitespaces', 'void_elements' );

our $GLOBAL_REGGRP  = 'global';

##########################################################################################

{
    no strict 'refs';

    foreach my $field ( @BOOLEAN_ACCESSORS ) {
        next if defined *{ __PACKAGE__ . '::' . $field }{CODE};

        *{ __PACKAGE__ . '::' . $field} = sub {
            my ( $self, $value ) = @_;

            $self->{'_' . $field} = $value ? 1 : undef if ( defined( $value ) );

            return $self->{'_' . $field};
        };
    }

    foreach my $reggrp ( @REGGRPS, $GLOBAL_REGGRP ) {
        next if defined *{ __PACKAGE__ . '::reggrp_' . $reggrp }{CODE};

        *{ __PACKAGE__ . '::reggrp_' . $reggrp } = sub {
            my ( $self ) = shift;

            return $self->{ '_reggrp_' . $reggrp };
        };
    }
}

sub do_javascript {
    my ( $self, $value ) = @_;

    if ( defined( $value ) ) {
        if ( grep( $value eq $_, @JAVASCRIPT_OPTS ) ) {
            $self->{_do_javascript} = $value;
        }
        elsif ( ! $value ) {
            $self->{_do_javascript} = undef;
        }
    }

    return $self->{_do_javascript};
}

sub do_stylesheet {
    my ( $self, $value ) = @_;

    if ( defined( $value ) ) {
        if ( grep( $value eq $_, @CSS_OPTS ) ) {
            $self->{_do_stylesheet} = $value;
        }
        elsif ( ! $value ) {
            $self->{_do_stylesheet} = undef;
        }
    }

    return $self->{_do_stylesheet};
}

# these variables are used in the closures defined in the init function
# below - we have to use globals as using $self within the closures leads
# to a reference cycle and thus memory leak, and we can't scope them to
# the init method as they may change. they are set by the minify sub
our $remove_comments;
our $remove_newlines;
our $html5;
our $do_javascript;
our $do_stylesheet;
our $js_packer;
our $css_packer;
our $reggrp_ws;

sub init {
    my $class = shift;
    my $self  = {};

    bless( $self, $class );

    $self->{whitespaces}->{reggrp_data}   = $WHITESPACES;
    $self->{newlines}->{reggrp_data}      = $NEWLINES;
    $self->{newlines_tags}->{reggrp_data} = $NEWLINES_TAGS;
    $self->{global}->{reggrp_data}        = [
        {
            regexp      => $DOCTYPE,
            replacement => sub {
                return '<!--~' . $_[0]->{store_index} . '~-->';
            },
            store => sub {
                my $doctype = $_[0]->{match};

                $doctype =~ s/\s+/ /gsm;

                return $doctype;
            }
        },
        {
            regexp      => $COMMENT,
            replacement => sub {
                return $remove_comments ? (
                    $remove_newlines ? ' ' : (
                        ( $_[0]->{submatches}->[0] =~ /\n/s or $_[0]->{submatches}->[2] =~ /\n/s ) ? "\n" : ''
                    )
                ) : '<!--~' . $_[0]->{store_index} . '~-->';
            },
            store => sub {
                my $ret = $remove_comments ? '' : (
                     ( ( not $remove_newlines and $_[0]->{submatches}->[0] =~ /\n/s ) ? "\n" : '' ) .
                     $_[0]->{submatches}->[1] .
                     ( ( not $remove_newlines and $_[0]->{submatches}->[2] =~ /\n/s ) ? "\n" : '' )
                );

                return $ret;
            }
        },
        {
            regexp      => $DONT_CLEAN,
            replacement => sub {
                return '<!--~' . $_[0]->{store_index} . '~-->';
            },
            store => sub {
                my ( $opening, undef, $content, $closing )  = @{$_[0]->{submatches}};

                if ( $content ) {
                    my $opening_script_re   = '<\s*script' . ( $html5 ? '[^>]*>' : '[^>]*(?:java|ecma)script[^>]*>' );
                    my $opening_style_re    = '<\s*style' . ( $html5 ? '[^>]*>' : '[^>]*text\/css[^>]*>' );
					my $js_type_re          = q{type=['"]((application|text)/){0,1}(x-){0,1}(java|ecma)script['"]};

                    if (
						$opening =~ /$opening_script_re/i
						&& ( $opening =~ /$js_type_re/i || $opening !~ /type/i )
					) {
                        $opening =~ s/ type="(text\/)?(java|ecma)script"//i if ( $html5 );

                        if ( $js_packer and $do_javascript ) {
                            $js_packer->minify( \$content, { compress => $do_javascript } );

                            unless ( $html5 ) {
                                $content = '/*<![CDATA[*/' . $content . '/*]]>*/';
                            }
                        }
                    }
                    elsif ( $opening =~ /$opening_style_re/i ) {
                        $opening =~ s/ type="text\/css"//i if ( $html5 );

                        if ( $css_packer and $do_stylesheet ) {
                            $css_packer->minify( \$content, { compress => $do_stylesheet } );
                            $content = "\n" . $content if ( $do_stylesheet eq 'pretty' );
                        }
                    }
                }
                else {
                    $content = '';
                }

                $reggrp_ws->exec( \$opening );
                $reggrp_ws->exec( \$closing );

                return $opening . $content . $closing;
            },
            modifier    => 'ism'
        }
    ];

    $self->{void_elements}->{reggrp_data} = [
        {
            regexp      => '<\s*((?:' . join( '|', @VOID_ELEMENTS ) . ')\b[^>]*)\s*\/>',
            replacement => sub {
                return '<' . $_[0]->{submatches}->[0] . '>';
            },
            modifier    => 'ism'
        }
    ];

    foreach ( @Packer::REGGRPS ) {
        $self->{ '_reggrp_' . $_ } = RegGrp->new( { reggrp => $self->{$_}->{reggrp_data} } );
    }

    $self->{ '_reggrp_' . $GLOBAL_REGGRP } = RegGrp->new(
        {
            reggrp          => $self->{$GLOBAL_REGGRP}->{reggrp_data},
            restore_pattern => qr/<!--~(\d+)~-->/
        }
    );

    return $self;
}

sub minify {
    my ( $self, $input, $opts );

    unless (
        ref( $_[0] ) and
        ref( $_[0] ) eq __PACKAGE__
    ) {
        $self = __PACKAGE__->init();

        shift( @_ ) unless ( ref( $_[0] ) );

        ( $input, $opts ) = @_;
    }
    else {
        ( $self, $input, $opts ) = @_;
    }

    if ( ref( $input ) ne 'SCALAR' ) {
        carp( 'First argument must be a scalarref!' );
        return undef;
    }

    my $html;
    my $cont    = 'void';

    if ( defined( wantarray ) ) {
        my $tmp_input = ref( $input ) ? ${$input} : $input;

        $html   = \$tmp_input;
        $cont   = 'scalar';
    }
    else {
        $html = ref( $input ) ? $input : \$input;
    }

    if ( ref( $opts ) eq 'HASH' ) {
        foreach my $field ( @BOOLEAN_ACCESSORS ) {
            $self->$field( $opts->{$field} ) if ( defined( $opts->{$field} ) );
        }

        $self->do_javascript( $opts->{do_javascript} ) if ( defined( $opts->{do_javascript} ) );
        $self->do_stylesheet( $opts->{do_stylesheet} ) if ( defined( $opts->{do_stylesheet} ) );
    }

    if ( not $self->no_compress_comment() and ${$html} =~ /$PACKER_COMMENT/s ) {
        my $compress = $1;
        if ( $compress eq '_no_compress_' ) {
            return ( $cont eq 'scalar' ) ? ${$html} : undef;
        }
    }

	# (re)initialize variables used in the closures
	$remove_comments = $self->remove_comments;
	$remove_newlines = $self->remove_newlines;
	$html5           = $self->html5;
	$do_javascript   = $self->do_javascript;
	$do_stylesheet   = $self->do_stylesheet;
	$js_packer       = $self->javascript_packer;
	$css_packer      = $self->css_packer;
	$reggrp_ws       = $self->reggrp_whitespaces;

    $self->reggrp_global()->exec( $html );
    $self->reggrp_whitespaces()->exec( $html );
    if ( $self->remove_newlines() ) {
        $self->reggrp_newlines_tags()->exec( $html );
        $self->reggrp_newlines()->exec( $html );
    }
    if ( $self->html5() ) {
        $self->reggrp_void_elements()->exec( $html );
    }

    $self->reggrp_global()->restore_stored( $html );

    return ${$html} if ( $cont eq 'scalar' );
}

sub javascript_packer {
    my $self = shift;

    unless ( $self->{_checked_javascript_packer} ) {
        eval "use JavaScript::Packer $REQUIRED_JAVASCRIPT_PACKER;";

        unless ( $@ ) {
            $self->{_javascript_packer} = eval {
                JavaScript::Packer->init();
            };
        }

        $self->{_checked_javascript_packer} = 1;
    }

    return $self->{_javascript_packer};
}

sub css_packer {
    my $self = shift;

    unless ( $self->{_checked_css_packer} ) {
        eval "use CSS::Packer $REQUIRED_CSS_PACKER;";

        unless ( $@ ) {
            $self->{_css_packer} = eval {
                CSS::Packer->init();
            };
        }

        $self->{_checked_css_packer} = 1;
    }

    return $self->{_css_packer};
}

1;

__END__

=head1 NAME

HTML::Packer - Another HTML code cleaner

=for html
<a href='https://travis-ci.org/leejo/html-packer-perl?branch=master'><img src='https://travis-ci.org/leejo/html-packer-perl.svg?branch=master' alt='Build Status' /></a>
<a href='https://coveralls.io/r/leejo/html-packer-perl'><img src='https://coveralls.io/repos/leejo/html-packer-perl/badge.png?branch=master' alt='Coverage Status' /></a>

=head1 VERSION

Version 2.04

=head1 DESCRIPTION

A HTML Compressor.

=head1 SYNOPSIS

    use HTML::Packer;

    my $packer = HTML::Packer->init();

    $packer->minify( $scalarref, $opts );

To return a scalar without changing the input simply use (e.g. example 2):

    my $ret = $packer->minify( $scalarref, $opts );

For backward compatibility it is still possible to call 'minify' as a function:

    HTML::Packer::minify( $scalarref, $opts );

First argument must be a scalarref of HTML-Code.
Second argument must be a hashref of options. Possible options are

=over 4

=item remove_comments

HTML-Comments will be removed if 'remove_comments' has a true value.

=item remove_newlines

ALL newlines will be removed if 'remove_newlines' has a true value.

=item do_javascript

Defines compression level for javascript. Possible values are 'clean', 'obfuscate', 'shrink' and 'best'.
Default is no compression for javascript.
This option only takes effect if L<JavaScript::Packer> is installed.

=item do_stylesheet

Defines compression level for CSS. Possible values are 'minify' and 'pretty'.
Default is no compression for CSS.
This option only takes effect if L<CSS::Packer> is installed.

=item no_compress_comment

If not set to a true value it is allowed to set a HTML comment that prevents the input being packed.

    <!-- HTML::Packer _no_compress_ -->

Is not set by default.

=item html5

If set to a true value closing slashes will be removed from void elements.

=back

=head1 AUTHOR

Merten Falk, C<< <nevesenin at cpan.org> >>. Now maintained by Lee
Johnson (LEEJO).

=head1 BUGS

Please report any bugs or feature requests through
the web interface at L<https://github.com/leejo/html-packer-perl/issues>. I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

perldoc HTML::Packer

=head1 COPYRIGHT & LICENSE

Copyright 2009 - 2011 Merten Falk, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 SEE ALSO

L<HTML::Clean>

=cut
