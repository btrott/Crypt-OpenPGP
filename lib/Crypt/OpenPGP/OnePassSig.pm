# $Id: OnePassSig.pm,v 1.2 2001/07/21 06:54:27 btrott Exp $

package Crypt::OpenPGP::OnePassSig;
use strict;

sub new { bless { }, $_[0] }

sub parse {
    my $class = shift;
    my($buf) = @_;
    my $onepass = $class->new;
    $onepass->{version} = $buf->get_int8;
    $onepass->{type} = $buf->get_int8;
    $onepass->{hash_alg} = $buf->get_int8;
    $onepass->{pk_alg} = $buf->get_int8;
    $onepass->{key_id} = $buf->get_bytes(8);
    $onepass->{nested} = $buf->get_int8;
    $onepass;
}

1;
