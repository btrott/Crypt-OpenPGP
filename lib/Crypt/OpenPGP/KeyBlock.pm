# $Id: KeyBlock.pm,v 1.3 2001/07/26 07:10:46 btrott Exp $

package Crypt::OpenPGP::KeyBlock;
use strict;

use Crypt::OpenPGP::PacketFactory;

sub primary_uid {
    $_[0]->{pkt}{ 'Crypt::OpenPGP::UserID' } ?
        $_[0]->{pkt}{ 'Crypt::OpenPGP::UserID' }->[0]->id : undef;
}

sub key { $_[0]->get('Crypt::OpenPGP::Certificate')->[0] }
sub subkey { $_[0]->get('Crypt::OpenPGP::Certificate')->[1] }

sub new { bless { pkt => { } }, $_[0] }

sub add {
    my $kb = shift;
    my($pkt) = @_;
    push @{ $kb->{pkt}->{ ref($pkt) } }, $pkt;
    push @{ $kb->{order} }, $pkt;
}

sub get { $_[0]->{pkt}->{ $_[1] } }

sub save {
    my $kb = shift;
    Crypt::OpenPGP::PacketFactory->save( @{ $kb->{order} } );
}

1;
