# $Id: OnePassSig.pm,v 1.3 2001/07/29 04:46:50 btrott Exp $

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
__END__

=head1 NAME

Crypt::OpenPGP::OnePassSig - One-Pass Signature packet

=head1 SYNOPSIS

    use Crypt::OpenPGP::OnePassSig;

    my $onepass = Crypt::OpenPGP::OnePassSig->parse($buffer);

=head1 DESCRIPTION

I<Crypt::OpenPGP::OnePassSig> implements a PGP One-Pass Signature
packet, a packet that precedes the signature data and contains
enough information to allow the receiver of the signature to begin
computing the hashed data. Standard signature packets always come
I<after> the signed data, which forces receivers to either read the
entire block of data into memory, or to skip past the data to get
to the signature, then backtrack to get back to the data.

The one-pass signature packet does not contain the actual signature
on the data, but it contains, for example, the ID of the digest
algorithm used to hash the data; this allows the receiver to create
a digest context and start adding the data from the data packet as
soon as it gets to the data packet. Thus no backtracking is necessary,
nor is it necessary to save all of the data in memory.

=head1 USAGE

=head2 my $onepass = Crypt::OpenPGP::OnePassSig->parse($buffer)

Given the I<Crypt::OpenPGP::Buffer> object buffer, which should
contain a one-pass signature packet, parses the object from the
buffer and returns the object.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut
