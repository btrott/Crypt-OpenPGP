# $Id: Trust.pm,v 1.2 2001/07/21 06:54:27 btrott Exp $

package Crypt::OpenPGP::Trust;
use strict;

use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub new { bless { }, $_[0] }
sub flags { $_[0]->{flags} }
sub parse {
    my $class = shift;
    my($buf) = @_;
    my $trust = $class->new;
    $trust->{flags} = $buf->get_int8;
    $trust;
}

1;
