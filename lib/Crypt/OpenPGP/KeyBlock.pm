# $Id: KeyBlock.pm,v 1.4 2001/07/29 04:32:02 btrott Exp $

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
__END__

=head1 NAME

Crypt::OpenPGP::KeyBlock - Key block object

=head1 SYNOPSIS

    use Crypt::OpenPGP::KeyBlock;

    my $kb = Crypt::OpenPGP::KeyBlock->new;
    $kb->add($packet);

    my $serialized = $kb->save;

=head1 DESCRIPTION

I<Crypt::OpenPGP::KeyBlock> represents a single keyblock in a keyring.
A key block is essentially just a set of associated keys containing
exactly one master key, zero or more subkeys, some user ID packets, some
signatures, etc. The key is that there is only one master key
associated with each keyblock.

=head1 USAGE

=head2 Crypt::OpenPGP::KeyBlock->new

Constructs a new key block object and returns that object.

=head2 $kb->add($packet)

Adds the packet I<$packet> to the key block.

=head2 $kb->save

Serializes each of the packets contained in the I<KeyBlock> object,
in order, and returns the serialized data. This output can then be
fed to I<Crypt::OpenPGP::Armour> for ASCII-armouring, for example,
or can be written out to a keyring file.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut
