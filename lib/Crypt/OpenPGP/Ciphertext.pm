# $Id: Ciphertext.pm,v 1.13 2001/07/29 06:29:52 btrott Exp $

package Crypt::OpenPGP::Ciphertext;
use strict;

use Crypt::OpenPGP::Cipher;
use Crypt::OpenPGP::Constants qw( DEFAULT_CIPHER );
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub new {
    my $class = shift;
    my $enc = bless { }, $class;
    $enc->init(@_);
}

sub init {
    my $enc = shift;
    my %param = @_;
    if ((my $key = $param{SymKey}) && (my $data = $param{Data})) {
        require Crypt::Random;
        my $alg = $param{Cipher} || DEFAULT_CIPHER;
        my $cipher = Crypt::OpenPGP::Cipher->new($alg, $key);
        my $bs = $cipher->blocksize;
        my $pad = Crypt::Random::makerandom_octet( Length => $bs );
        $pad .= substr $pad, -2, 2;
        $enc->{ciphertext} = $cipher->encrypt($pad);
        $cipher->decrypt(substr $enc->{ciphertext}, 2, $bs);   ## resync
        $enc->{ciphertext} .= $cipher->encrypt($data);
    }
    $enc;
}

sub parse {
    my $class = shift;
    my($buf) = @_;
    my $enc = $class->new;
    $enc->{ciphertext} = $buf->get_bytes($buf->length);
    $enc;
}

sub save { $_[0]->{ciphertext} }

sub decrypt {
    my $enc = shift;
    my($key, $sym_alg) = @_;
    my $cipher = Crypt::OpenPGP::Cipher->new($sym_alg, $key) or
        return $enc->error( Crypt::OpenPGP::Cipher->errstr );
    my $padlen = $cipher->blocksize + 2;
    my $pt = $cipher->decrypt(substr $enc->{ciphertext}, 0, $padlen);
    return $enc->error("Bad checksum")
        unless substr($pt, -4, 2) eq substr($pt, -2, 2);
    $cipher->decrypt(substr $enc->{ciphertext}, $padlen);
}

1;
__END__

=head1 NAME

Crypt::OpenPGP::Ciphertext - Encrypted data packet

=head1 SYNOPSIS

    use Crypt::OpenPGP::Ciphertext;

    my $key_data = 'f' x 64;    ## Not a very good key :)

    my $ct = Crypt::OpenPGP::Ciphertext->new(
                              Data   => "foo bar baz",
                              SymKey => $key_data,
                    );
    my $serialized = $ct->save;

    my $ct = Crypt::OpenPGP::Ciphertext->parse($buffer);
    my $data = $ct->decrypt($key_data);

=head1 DESCRIPTION

I<Crypt::OpenPGP::Ciphertext> implements symmetrically encrypted data
packets, providing both encryption and decryption functionality. The
encryption used in these packets is described in the OpenPGP RFC, in
section 12.8 (OpenPGP CFB mode). It is a variant in standard CFB, and
it differs slightly from the CFB used to encrypt secret key data.

=head1 USAGE

=head2 Crypt::OpenPGP::Ciphertext->new( %arg )

Creates a new symmetrically encrypted data packet object and returns
that object. If there are no arguments in I<%arg>, the object is
created with an empty data container; this is used, for example, in
I<parse> (below), to create an empty packet which is then filled from
the data in the buffer.

If you wish to initialize a non-empty object, I<%arg> can contain:

=over 4

=item * Data

A block of octets that make up the plaintext data to be encrypted.

This argument is required (for a non-empty object).

=item * SymKey

The symmetric cipher key: a string of octets that make up the key data
of the symmetric cipher key. This should be at least long enough for
the key length of your chosen cipher (see I<Cipher>, below), or, if
you have not specified a cipher, at least 64 bytes (to allow for
long cipher key sizes).

This argument is required (for a non-empty object).

=item * Cipher

The name (or ID) of a supported PGP cipher. See I<Crypt::OpenPGP::Cipher>
for a list of valid cipher names.

This argument is optional; by default I<Crypt::OpenPGP::Cipher> will
use C<DES3>.

=back

=head2 $ct->save

Returns the block of ciphertext created in I<new> (assuming that you
created a non-empty packet by specifying some data; otherwise returns
an empty string).

=head2 Crypt::OpenPGP::Ciphertext->parse($buffer)

Given I<$buffer>, a I<Crypt::OpenPGP::Buffer> object holding (or
with offset pointing to) a symmetrically encrypted data packet, returns
a new I<Crypt::OpenPGP::Ciphertext> object, initialized with the
ciphertext in the buffer.

=head2 $ct->decrypt($key, $alg)

Decrypts the ciphertext in the I<Crypt::OpenPGP::Ciphertext> object
and returns the plaintext. I<$key> is the encryption key, and I<$alg>
is the name (or ID) of the I<Crypt::OpenPGP::Cipher> type used to
encrypt the message. Obviously you can't just guess at these
parameters; this method (along with I<parse>, above) is best used along
with the I<Crypt::OpenPGP::SessionKey> object, which holds an encrypted
version of the key and cipher algorithm.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut
