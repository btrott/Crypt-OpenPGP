# $Id: Marker.pm,v 1.1 2001/07/26 19:23:22 btrott Exp $

package Crypt::OpenPGP::Marker;
use strict;

use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub new { bless { }, $_[0] }
sub parse {
    my $class = shift;
    my($buf) = @_;
    my $marker = $class->new;
    $marker->{mark} = $buf->bytes;
    $marker;
}

1;
