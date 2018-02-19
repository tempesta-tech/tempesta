package Data;

use 5.008009;
use warnings;
use strict;
use Carp;

our @ACCESSORS = ( 'regexp', 'replacement', 'store', 'restore_pattern' );

##########################################################################################

{
    no strict 'refs';

    foreach my $field ( @ACCESSORS ) {
        next if defined *{'Data::' . $field}{CODE};

        *{'Data::' . $field} = sub {
            my $self = shift;

            return $self->{'_' . $field};
        };
    }
}

sub new {
    my ( $class, $in_ref )  = @_;
    my $self                = {};

    bless( $self, $class );

    unless ( $in_ref->{regexp} ) {
        carp( 'Value for key "regexp" must be a scalar or a regexp object!' );
        return;
    }

    foreach my $accessor ( @ACCESSORS ) {
        if ( $accessor eq 'regexp' || $accessor eq 'restore_pattern' ) {
            if (
                ref( $in_ref->{$accessor} ) and
                ref( $in_ref->{$accessor} ) ne 'Regexp'
            ) {
                carp( 'Value for key "' . $accessor . '" must be a scalar or a regexp object!' );
                return;
            }
        }
        elsif ( $accessor eq 'replacement' || $accessor eq 'store' ) {
            if (
                ref( $in_ref->{$accessor} ) and
                ref( $in_ref->{$accessor} ) ne 'CODE'
            ) {
                carp( 'Value for key "' . $accessor . '" must be a scalar or a code reference!' );
                return;
            }
        }
    }

    if ( ref( $in_ref->{modifier} ) ) {
        carp( 'Value for key "modifier" must be a scalar!' );
        return;
    }

    $self->{_regexp}            = $in_ref->{regexp};
    $self->{_replacement}       = defined( $in_ref->{store} ) ? (
        $in_ref->{restore_pattern} ? $in_ref->{replacement} : sub {
            return sprintf( "\x01%d\x01", $_[0]->{store_index} );
        }
    ) : $in_ref->{replacement};
    $self->{_store}             = $in_ref->{store};

    if ( defined( $in_ref->{modifier} ) || ! ref( $in_ref->{regexp} ) ) {
        my $modifier = defined( $in_ref->{modifier} ) ? $in_ref->{modifier} : 'sm';

        $self->{_regexp} =~ s/^\(\?[\^dlupimsx-]+:(.*)\)$/$1/si;
        $self->{_regexp} = sprintf( '(?%s:%s)', $modifier, $self->{_regexp} );
    }

    my $restore_pattern         = $in_ref->{restore_pattern} || qr~\x01(\d+)\x01~;
    $self->{_restore_pattern}   = qr/$restore_pattern/;

    return $self;
}

1;
