# $Id: OpenPGP.pm,v 1.49 2001/07/29 13:47:04 btrott Exp $

package Crypt::OpenPGP;
use strict;

use vars qw( $VERSION );
$VERSION = '0.11';

use Crypt::OpenPGP::Constants qw( DEFAULT_CIPHER );
use Crypt::OpenPGP::KeyRing;
use Crypt::OpenPGP::Plaintext;
use Crypt::OpenPGP::Message;
use Crypt::OpenPGP::PacketFactory;

use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

use vars qw( %DEFAULTS %COMPAT );

{
    my $env = sub {
        my $dir = shift; my @paths;
        if (exists $ENV{$dir}) { for (@_) { push @paths, "$ENV{$dir}/$_" } }
        return @paths ? @paths : "";
    };

    %DEFAULTS = (
        PubRing => [ $env->('PGPPATH','pubring.pgp', 'pubring.pkr'),
                     $env->('HOME', '.pgp/pubring.pgp', '.pgp/pubring.pkr'),
                     $env->('GNUPGHOME', 'pubring.gpg'),
                     $env->('HOME', '.gnupg/pubring.gpg'),
                   ],

        SecRing => [ $env->('PGPPATH','secring.pgp', 'secring.skr'),
                     $env->('HOME', '.pgp/secring.pgp', '.pgp/secring.skr'),
                     $env->('GNUPGHOME', 'secring.gpg'),
                     $env->('HOME', '.gnupg/secring.gpg'),
                   ],
    );
}

%COMPAT = (
    PGP2 => {
              'sign'    => { Digest => 'MD5', Version => 3 },
              'encrypt' => { Cipher => 'IDEA', Compress => 'ZIP' },
              'keygen'  => { Type => 'RSA', Cipher => 'IDEA',
                             Version => 3, Digest => 'MD5' },
    },

    PGP5 => {
              'sign'    => { Digest => 'SHA1', Version => 3 },
              'encrypt' => { Cipher => 'DES3', Compress => 'ZIP' },
              'keygen'  => { Type => 'DSA', Cipher => 'DES3',
                             Version => 4, Digest => 'SHA1' },
    },

    GnuPG => {
              'sign'    => { Digest => 'RIPEMD160', Version => 4 },
              'encrypt' => { Cipher => 'Rijndael', Compress => 'Zlib' },
              'keygen'  => { Type => 'DSA', Cipher => 'Rijndael',
                             Version => 4, Digest => 'RIPEMD160' },
    },
);

sub version_string { __PACKAGE__ . ' ' . $VERSION }

sub new {
    my $class = shift;
    my $pgp = bless { }, $class;
    $pgp->init(@_);
}

sub init {
    my $pgp = shift;
    my %param = @_;
    ## XXX fix, read options from GnuPG options file, etc.?
    $pgp->{$_} = $param{$_} for keys %param;
    for my $s (qw( PubRing SecRing )) {
        unless (defined $pgp->{$s}) {
            for my $ring (@{ $DEFAULTS{$s} }) {
                next unless $ring; 
                $pgp->{$s} = $ring, last if -e $ring;
            }
        }
    }
    $pgp;
}

sub sign {
    my $pgp = shift;
    my %param = @_;
    $pgp->_merge_compat(\%param, 'sign') or
        return $pgp->error( $pgp->errstr );
    my($cert, $data);
    require Crypt::OpenPGP::Signature;
    unless ($data = $param{Data}) {
        my $file = $param{Filename} or
            return $pgp->error("Need either 'Data' or 'Filename' to sign");
        $data = $pgp->_read_files($file) or
            return $pgp->error($pgp->errstr);
    }
    unless ($cert = $param{Key}) {
        my $kid = $param{KeyID} or return $pgp->error("No KeyID specified");
        my $ring = Crypt::OpenPGP::KeyRing->new( Filename => $pgp->{SecRing} );
        (my($kb), $cert) = $ring->find_keyblock_by_keyid(pack 'H*', $kid);
        return $pgp->error("Could not find secret key with KeyID $kid")
            unless $kb && $cert;
    }
    if ($cert->is_protected) {
        my $pass = $param{Passphrase} or
            return $pgp->error("Need passphrase to decrypt secret key");
        $cert->unlock($pass) or
            return $pgp->error("Secret key unlock failed: " . $cert->errstr);
    }
    my $pt = Crypt::OpenPGP::Plaintext->new( Data => $data,
                      $param{Filename} ? (Filename => $param{Filename}) : () );
    my %hash_args;
    if (my $hash_alg = $param{Digest}) {
        my $dgst = Crypt::OpenPGP::Digest->new($hash_alg) or
            return $pgp->error( Crypt::OpenPGP::Digest->errstr );
        %hash_args = ( Digest => $dgst->alg_id );
    }
    my $sig = Crypt::OpenPGP::Signature->new(
                          Data => $pt,
                          Key  => $cert,
                          Version => $param{Version},
                          %hash_args,
                 );
    my $sig_data = Crypt::OpenPGP::PacketFactory->save($sig,
        $param{Detach} ? () : ($pt));
    if ($param{Armour}) {
        require Crypt::OpenPGP::Armour;
        $sig_data = Crypt::OpenPGP::Armour->armour(
                          Data => $sig_data,
                          Object => ($param{Detach} ? 'SIGNATURE' : 'MESSAGE'),
                 ) or return $pgp->error( Crypt::OpenPGP::Armour->errstr );
    }
    $sig_data;
}

## Could be verifying either a detached signature,
## or a "message" containing both signature and original
## data. The "message" can, in turn, be either:
##     onepass-sig, data, signature
## or
##     signature, data
## so we need to be able to read both formats
sub verify {
    my $pgp = shift;
    my %param = @_;
    my($data, $sig);
    require Crypt::OpenPGP::Signature;
    $param{Signature} or $param{SigFile} or
            return $pgp->error("Need Signature or SigFile to verify");
    my %arg = $param{Signature} ? (Data => $param{Signature}) :
                                  (Filename => $param{SigFile});
    my $msg = Crypt::OpenPGP::Message->new;
    $msg->read( %arg ) or
        return $pgp->error("Reading signature failed: " . $msg->errstr);
    my @pieces = @{ $msg->{pieces} };
    if (ref($pieces[0]) eq 'Crypt::OpenPGP::Compressed') {
        $data = $pieces[0]->decompress or
            return $pgp->error("Decompression error: " . $pieces[0]->errstr);
        $msg->read( Data => $data) or
            return $pgp->error("Reading decompressed data failed: " .
                $msg->errstr);
        @pieces = @{ $msg->{pieces} };
    }
    if (ref($pieces[0]) eq 'Crypt::OpenPGP::OnePassSig') {
        ($data, $sig) = @pieces[1,2];
    } elsif (ref($pieces[0]) eq 'Crypt::OpenPGP::Signature') {
        ($sig, $data) = @pieces[0,1];
    } else {
        return $pgp->error("SigFile contents are strange");
    }
    unless ($data) {
        if ($param{Data}) {
            $data = Crypt::OpenPGP::Plaintext->new( Data => $param{Data} );
        }
        else {
            ## if no Signature or detached sig in SigFile
            my @files = ref($param{Files}) eq 'ARRAY' ? @{ $param{Files} } :
                            $param{Files};
            my $fdata = $pgp->_read_files(@files);
            return $pgp->error("Reading data files failed: " . $pgp->errstr)
                unless defined $fdata;
            $data = Crypt::OpenPGP::Plaintext->new( Data => $fdata );
       }
    }
    my $key_id = $sig->key_id;
    my $ring = Crypt::OpenPGP::KeyRing->new( Filename => $pgp->{PubRing} );
    my($kb, $cert) = $ring->find_keyblock_by_keyid($key_id);
    return $pgp->error("Could not find public key with KeyID " .
        unpack('H*', $key_id)) unless $kb && $cert;
    my $dgst = $sig->hash_data($data) or
        return $pgp->error( $sig->errstr );
    $cert->key->public_key->verify($sig, $dgst) ?
        ($kb->primary_uid || 1) : 0;
}

sub encrypt {
    my $pgp = shift;
    my %param = @_;
    $pgp->_merge_compat(\%param, 'encrypt') or
        return $pgp->error( $pgp->errstr );
    my($data, $cert);
    require Crypt::OpenPGP::Cipher;
    require Crypt::OpenPGP::Ciphertext;
    unless ($data = $param{Data}) {
        my $file = $param{Filename} or
            return $pgp->error("Need either 'Data' or 'Filename' to encrypt");
        $data = $pgp->_read_files($file) or return $pgp->error($pgp->errstr);
    }
    my $pt = Crypt::OpenPGP::Plaintext->new( Data => $data,
                      $param{Filename} ? (Filename => $param{Filename}) : () );
    my $ptdata = Crypt::OpenPGP::PacketFactory->save($pt);
    if (my $alg = $param{Compress}) {
        require Crypt::OpenPGP::Compressed;
        $alg = Crypt::OpenPGP::Compressed->alg_id($alg);
        my $cdata = Crypt::OpenPGP::Compressed->new( Data => $ptdata,
            Alg => $alg ) or return $pgp->error("Compression error: " .
                Crypt::OpenPGP::Compressed->errstr);
        $ptdata = Crypt::OpenPGP::PacketFactory->save($cdata);
    }
    require Crypt::Random;
    my $key_data = Crypt::Random::makerandom_octet( Length => 32 );
    my $sym_alg = $param{Cipher} ?
        Crypt::OpenPGP::Cipher->alg_id($param{Cipher}) : DEFAULT_CIPHER;
    my($sym_key);
    if (($cert = $param{Key}) || ($param{KeyID})) {
        require Crypt::OpenPGP::SessionKey;
        unless ($cert) {
            my $kid = $param{KeyID};
            my $ring = Crypt::OpenPGP::KeyRing->new( Filename =>
                $pgp->{PubRing} );
            (my($kb), $cert) = $ring->find_keyblock_by_keyid(pack 'H*', $kid);
            return $pgp->error("Could not find public key with KeyID $kid")
                unless $kb && $cert;
        }
        $sym_key = Crypt::OpenPGP::SessionKey->new(
                            Key    => $cert,
                            SymKey => $key_data,
                            Cipher => $sym_alg,
                      ) or
            return $pgp->error( Crypt::OpenPGP::SessionKey->errstr );
    }
    elsif (my $pass = $param{Passphrase}) {
        require Crypt::OpenPGP::SKSessionKey;
        require Crypt::OpenPGP::S2k;
        my $s2k = Crypt::OpenPGP::S2k->new('Salt_Iter');
        my $keysize = Crypt::OpenPGP::Cipher->new($sym_alg)->keysize;
        $key_data = $s2k->generate($pass, $keysize);
        $sym_key = Crypt::OpenPGP::SKSessionKey->new(
                            Passphrase => $pass,
                            SymKey     => $key_data,
                            Cipher     => $sym_alg,
                            S2k        => $s2k,
                      ) or
            return $pgp->error( Crypt::OpenPGP::SKSessionKey->errstr );
    } else {
        return $pgp->error("Need something to encrypt with");
    }
    my $enc = Crypt::OpenPGP::Ciphertext->new(
                        SymKey => $key_data,
                        Data   => $ptdata,
                        Cipher => $sym_alg,
                  );
    my $enc_data = Crypt::OpenPGP::PacketFactory->save($sym_key, $enc);
    if ($param{Armour}) {
        require Crypt::OpenPGP::Armour;
        $enc_data = Crypt::OpenPGP::Armour->armour(
                          Data => $enc_data,
                          Object => 'MESSAGE',
                 ) or return $pgp->error( Crypt::OpenPGP::Armour->errstr );
    }
    $enc_data;
}

sub decrypt {
    my $pgp = shift;
    my %param = @_;
    my($data);
    unless ($data = $param{Data}) {
        my $file = $param{Filename} or
            return $pgp->error("Need either 'Data' or 'Filename' to decrypt");
        $data = $pgp->_read_files($file) or return $pgp->error($pgp->errstr);
    }
    my $msg = Crypt::OpenPGP::Message->new;
    $msg->read( Data => $data ) or
        return $pgp->error("Reading data packets failed: " . $msg->errstr);
    return $pgp->error("No packets found in message") unless
        $msg->{pieces} && @{ $msg->{pieces} };
    my @pieces = @{ $msg->{pieces} };
    while (ref($pieces[0]) eq 'Crypt::OpenPGP::Marker') {
        shift @pieces;
    }
    my($key, $alg);
    if (ref($pieces[0]) eq 'Crypt::OpenPGP::SessionKey') {
        my $sym_key = shift @pieces;
        my $ring = Crypt::OpenPGP::KeyRing->new( Filename => $pgp->{SecRing} );
        my($kb, $cert) = $ring->find_keyblock_by_keyid($sym_key->key_id);
        return $pgp->error("Can't find key with ID " .
            unpack('H*', $sym_key->key_id)) unless $kb && $cert;
        if ($cert->is_protected) {
            my $pass = $param{Passphrase} or
                return $pgp->error("Need passphrase to decrypt secret key");
            $cert->unlock($pass) or
                return $pgp->error("Seckey unlock failed: " . $cert->errstr);
        }
        ($key, $alg) = $sym_key->decrypt($cert) or
            return $pgp->error("Symkey decrypt failed: " . $sym_key->errstr);
    }
    elsif (ref($pieces[0]) eq 'Crypt::OpenPGP::SKSessionKey') {
        my $sym_key = shift @pieces;
        my $pass = $param{Passphrase} or
            return $pgp->error("Need passphrase to decrypt session key");
        ($key, $alg) = $sym_key->decrypt($pass) or
            return $pgp->error("Symkey decrypt failed: " . $sym_key->errstr);
    }
    my $enc = $pieces[0];
    $data = $enc->decrypt($key, $alg) or
        return $pgp->error("Ciphertext decrypt failed: " . $enc->errstr);
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->append($data);
    my $pt = Crypt::OpenPGP::PacketFactory->parse($buf);
    if (ref($pt) eq 'Crypt::OpenPGP::Compressed') {
        $data = $pt->decompress or
            return $pgp->error("Decompression error: " . $pt->errstr);
        $buf = Crypt::OpenPGP::Buffer->new;
        $buf->append($data);
        $pt = Crypt::OpenPGP::PacketFactory->parse($buf);
    }
    $pt->data;
}

sub keygen {
    my $pgp = shift;
    my %param = @_;
    require Crypt::OpenPGP::Certificate;
    require Crypt::OpenPGP::Key;
    require Crypt::OpenPGP::KeyBlock;
    require Crypt::OpenPGP::Signature;
    require Crypt::OpenPGP::UserID;

    $param{Type} or
        return $pgp->error("Need a Type of key to generate");
    $param{Size} ||= 1024;
    $param{Version} ||= 4;
    $param{Version} = 3 if $param{Type} eq 'RSA';

    my $kb_pub = Crypt::OpenPGP::KeyBlock->new;
    my $kb_sec = Crypt::OpenPGP::KeyBlock->new;

    my($pub, $sec) = Crypt::OpenPGP::Key->keygen($param{Type}, %param);
    die Crypt::OpenPGP::Key->errstr unless $pub && $sec;
    my $pubcert = Crypt::OpenPGP::Certificate->new(
                             Key        => $pub,
                             Version    => $param{Version}
                ) or
        die Crypt::OpenPGP::Certificate->errstr;
    my $seccert = Crypt::OpenPGP::Certificate->new(
                             Key        => $sec,
                             Passphrase => $param{Passphrase},
                             Version    => $param{Version}
                ) or
        die Crypt::OpenPGP::Certificate->errstr;
    $kb_pub->add($pubcert);
    $kb_sec->add($seccert);

    my $id = Crypt::OpenPGP::UserID->new( Identity => $param{Identity} );
    $kb_pub->add($id);
    $kb_sec->add($id);

    my $sig = Crypt::OpenPGP::Signature->new(
                             Data    => $pubcert,
                             Key     => $seccert,
                             Version => $param{Version},
                             Type    => 0x13,
               );
    $kb_pub->add($sig);
    $kb_sec->add($sig);

    ($kb_pub, $kb_sec);
}

sub _read_files {
    my $pgp = shift;
    return $pgp->error("No files specified") unless @_;
    my @files = @_;
    my $data = '';
    for my $file (@files) {
        $file ||= '';
        local *FH;
        open FH, $file or return $pgp->error("Error opening $file: $!");
        { local $/; $data .= <FH> }
        close FH or warn "Warning: Got error closing $file: $!";
    }
    $data;
}

sub _merge_compat {
    my $pgp = shift;
    my($param, $meth) = @_;
    my $compat = $param->{Compat} or return 1;
    my $ref = $COMPAT{$compat}{$meth} or
        return $pgp->error("No settings for Compat class '$compat'");
    for my $arg (keys %$ref) {
        $param->{$arg} = $ref->{$arg} unless exists $param->{$arg};
    }
    1;
}

1;

__END__

=head1 NAME

Crypt::OpenPGP - Pure-Perl OpenPGP implementation

=head1 SYNOPSIS

    my $pgp = Crypt::OpenPGP->new;
    my $signature = $pgp->sign(
                   Filename   => $file,
                   KeyID      => $key_id,
                   Passphrase => $pass,
                   Detach     => 1,
                   Armour     => 1,
             );

    my $valid = $pgp->verify(
                   Signature  => $signature,
                   Files      => [ $file ],
             );

    my $ciphertext = $pgp->encrypt(
                   Filename   => $file,
                   KeyID      => $key_id,
                   Armour     => 1,
             );

    my $plaintext = $pgp->decrypt(
                   Data       => $ciphertext,
                   Passphrase => $pass,
             );

=head1 DESCRIPTION

I<Crypt::OpenPGP> is a pure-Perl implementation of the OpenPGP
standard[1]. In addition to support for the standard itself,
I<Crypt::OpenPGP> claims compatibility with many other PGP implementations,
both those that support the standard and those that preceded it.

I<Crypt::OpenPGP> provides signing/verification, encryption/decryption,
keyring management, and key-pair generation; in short it should provide
you with everything you need to PGP-enable yourself. Alternatively it
can be used as part of a larger system; for example, perhaps you have
a web-form-to-email generator written in Perl, and you'd like to encrypt
outgoing messages, because they contain sensitive information.
I<Crypt::OpenPGP> can be plugged into such a scenario, given your public
key, and told to encrypt all messages; they will then be readable only
by you.

This module currently supports C<RSA> and C<DSA> for digital signatures,
and C<RSA> and C<ElGamal> for encryption/decryption. It supports the
symmetric ciphers C<3DES>, C<Blowfish>, C<IDEA>, C<Twofish>, and
C<Rijndael> (C<AES>). C<Rijndael> is supported for key sizes of C<128>,
C<192>, and C<256> bits. I<Crypt::OpenPGP> supports the digest algorithms
C<MD5>, C<SHA-1>, and C<RIPE-MD/160>. And it supports C<ZIP> and C<Zlib>
compression.

=head1 COMPATIBILITY

One of the highest priorities for I<Crypt::OpenPGP> is compatibility with
other PGP implementations, including PGP implementations that existed
before the OpenPGP standard.

As a means towards that end, some of the high-level I<Crypt::OpenPGP>
methods can be used in compatibility mode; given an argument I<Compat>
and a PGP implementation with which they should be compatible, these
method will do their best to choose ciphers, digest algorithms, etc. that
are compatible with that implementation. For example, PGP2 only supports
C<IDEA> encryption, C<MD5> digests, and version 3 signature formats; if
you tell I<Crypt::OpenPGP> that it must be compatible with PGP2, it will
only use these algorithms/formats when encrypting and signing data.

To use this feature, supply either I<sign> or I<encrypt> with the
I<Compat> parameter, giving it one of the values from the list below.
For example:

    my $ct = $pgp->encrypt(
                  Compat   => 'PGP2',
                  Filename => 'foo.pl',
                  KeyID    => $key_id,
             );

Because I<PGP2> was specified, the data will automatically be encrypted
using the C<IDEA> cipher, and will be compressed using C<ZIP>.

Here is a list of the current compatibility sets and the algorithms and
formats they support.

=over 4

=item * PGP2

Encryption: symmetric cipher = C<IDEA>, compression = C<ZIP>

Signing: digest = C<MD5>, packet format = version 3

=item * PGP5

Encryption: symmetric cipher = C<3DES>, compression = C<ZIP>

Signing: digest = C<SHA-1>, packet format = version 3

=item * GnuPG

Encryption: symmetric cipher = C<Rijndael>, compression = C<Zlib>

Signing: digest = C<RIPE-MD/160>, packet format = version 4

=back

If the compatibility setting is unspecified (that is, if no I<Compat>
argument is supplied), the settings (ciphers, digests, etc.) fall
back to their default settings.

=head1 USAGE

I<Crypt::OpenPGP> has the following high-level interface. On failure,
all methods will return C<undef> and set the I<errstr> for the object;
look below at the I<ERROR HANDLING> section for more information.

=head2 Crypt::OpenPGP->new( %args )

Constructs a new I<Crypt::OpenPGP> instance and returns that object.
Returns C<undef> on failure.

I<%args> can contain:

=over 4

=item * SecRing

Path to your secret keyring. If unspecified, I<Crypt::OpenPGP> will look
for your keyring in a number of default places.

=item * PubRing

Path to your public keyring. If unspecified, I<Crypt::OpenPGP> will look
for your keyring in a number of default places.

=back

=head2 $pgp->encrypt( %args )

Encrypts a block of data. The encryption is actually done with a symmetric
cipher; the key for the symmetric cipher is then encrypted with either
the public key of the recipient or using a passphrase that you enter. The
former case is using public-key cryptography, the latter, standard
symmetric ciphers. In the first case, the session key can only be
unlocked by someone with the corresponding secret key; in the second, it
can only be unlocked by someone who knows the passphrase.

Returns a block of data containing two PGP packets: the encrypted
symmetric key and the encrypted data.

On failure returns C<undef>.

I<%args> can contain:

=over 4

=item * Compat

Specifies the PGP compatibility setting. See I<COMPATIBILITY>, above.

=item * Data

The plaintext to be encrypted. This should be a simple scalar containing
an arbitrary amount of data.

I<Data> is optional; if unspecified, you should specify a filename (see
I<Filename>, below).

=item * Filename

The path to a file to encrypt.

I<Filename> is optional; if unspecified, you should specify the data
in I<Data>, above. If both I<Data> and I<Filename> are specified, the
data in I<Data> overrides that in I<Filename>.

=item * KeyID

The ID of the public key that should be used to decrypt the symmetric
key. In other words, the ID of the key with which the message should
be encrypted. The value of the key ID should be specified as a 16-digit
hexadecimal number.

This argument is optional; if not provided you should provide the
I<Passphrase> option (below) to perform symmetric-key encryption when
encrypting the session key.

=item * Passphrase

The mechanism to use symmetric-key, or "conventional", encryption,
when encrypting the session key. In other words, this allows you to
use I<Crypt::OpenPGP> for encryption/decryption without using public-key
cryptography; this can be useful in certain circumstances (for example,
when encrypting data locally on disk).

This argument is optional; if not provided you should provide the
I<KeyID> option (above) to perform public-key encryption when encrypting
the session key.

=item * Cipher

The name of a symmetric cipher with which the plaintext will be
encrypted. Valid arguments are C<DES3>, C<Blowfish>, C<IDEA>,
C<Twofish>, C<Rijndael>, C<Rijndael192>, and C<Rijndael256> (the last
two are C<Rijndael> with key sizes of 192 and 256 bits, respectively).

This argument is optional; I<Crypt::OpenPGP> currently defaults to
C<DES3>, but this could change in the future.

=item * Compress

The name of a compression algorithm with which the plaintext will be
compressed before it is encrypted. Valid values are C<ZIP> and
C<Zlib>.

By default text is not compressed.

=item * Armour

If true, the data returned from I<encrypt> will be ASCII-armoured. This
can be useful when you need to send data through email, for example.

By default the returned data is not armoured.

=back

=head2 $pgp->decrypt( %args )

Decrypts a block of ciphertext. The ciphertext should be of the sort
returned from I<encrypt>, in either armoured or non-armoured form.
This is compatible with all other implementations of PGP: the output
of their encryption should serves as the input to this method.

Returns the plaintext (that is, the decrypted ciphertext).

On failure returns C<undef>.

I<%args> can contain:

=over 4

=item * Data

The ciphertext to be decrypted. This should be a simple scalar containing
an arbitrary amount of data.

I<Data> is optional; if unspecified, you should specify a filename (see
I<Filename>, below).

=item * Filename

The path to a file to decrypt.

I<Filename> is optional; if unspecified, you should specify the data
in I<Data>, above. If both I<Data> and I<Filename> are specified, the
data in I<Data> overrides that in I<Filename>.

=item * Passphrase

The passphrase to unlock your secret key.

This argument is mandatory if your secret key is protected.

=back

=head2 $pgp->sign( %args )

Creates and returns a digital signature on a block of data.

On failure returns C<undef>.

I<%args> can contain:

=over 4

=item * Compat

Specifies the PGP compatibility setting. See I<COMPATIBILITY>, above.

=item * Data

The text to be signed. This should be a simple scalar containing an
arbitrary amount of data.

I<Data> is optional; if unspecified, you should specify a filename (see
I<Filename>, below).

=item * Filename

The path to a file to sign.

I<Filename> is optional; if unspecified, you should specify the data
in I<Data>, above. If both I<Data> and I<Filename> are specified, the
data in I<Data> overrides that in I<Filename>.

=item * Detach

If set to a true value the signature created will be a detached
signature; that is, a signature that does not contain the original
text. This assumes that the person who will be verifying the signature
can somehow obtain the original text (for example, if you sign the text
of an email message, the original text is the message).

By default signatures are not detached.

=item * Armour

If true, the data returned from I<sign> will be ASCII-armoured. This
can be useful when you need to send data through email, for example.

By default the returned signature is not armoured.

=item * KeyID

The ID of the secret key that should be used to sign the message. The
value of the key ID should be specified as a 16-digit hexadecimal number.

This argument is mandatory.

=item * Passphrase

The passphrase to unlock your secret key.

This argument is mandatory if your secret key is protected.

=item * Digest

The digest algorithm to use when creating the signature; the data to be
signed is hashed by a message digest algorithm, then signed. Possible
values are C<MD5>, C<SHA1>, and C<RIPEMD160>.

This argument is optional; by default I<SHA1> will be used.

=item * Version

The format version of the created signature. The two possible values
are C<3> and C<4>; version 4 signatures will not be compatible with
older PGP implementations.

The default value is C<4>, although this could change in the future.

=back

=head2 $pgp->verify( %args )

Verifies a digital signature. Returns true on success, C<undef> on
failure. The 'true' value returned on success will be, if available,
the PGP User ID of the person who created the signature. If that
value is unavailable, the return value will be C<1>.

I<%args> can contain:

=over 4

=item * Signature

The signature data, as returned from I<sign>. This data can be either
a detached signature or a non-detached signature. If the former, you
will need to specify the list of files comprising the original signed
data (see I<Data> or I<Files>, below).

Either this argument or I<SigFile> is required.

=item * SigFile

The path to a file containing the signature data. This data can be either
a detached signature or a non-detached signature. If the former, you
will need to specify the list of files comprising the original signed
data (see I<Data> or I<Files>, below).

Either this argument or I<SigFile> is required.

=item * Data

Specifies the original signed data.

If the signature (in either I<Signature> or I<SigFile>) is a detached
signature, either I<Data> or I<Files> is a mandatory argument.

=item * Files

Specifies a list of files comprising the original signed data. The
value should be a reference to a list of file paths; if there is only
one file, the value can be specified as a scalar string, rather than
a reference to a list.

If the signature (in either I<Signature> or I<SigFile>) is a detached
signature, either I<Data> or I<Files> is a mandatory argument.

=back

=head2 $pgp->keygen( %args )

NOTE: this interface is alpha and could change in future releases!

Generates a public/secret PGP keypair. Returns two keyblocks (objects
of type I<Crypt::OpenPGP::KeyBlock>), a public and a secret keyblock,
respectively. A keyblock is essentially a block of keys, subkeys,
signatures, and user ID PGP packets.

I<%args> can contain:

=over 4

=item * Type

The type of key to generate. Currently there are two valid values:
C<RSA> and C<DSA>. C<ElGamal> key generation is not supported at the
moment.

This is a required argument.

=item * Size

Bitsize of the key to be generated. This should be an even integer;
there is no low end currently implemented in I<Crypt::OpenPGP>, but
for the sake of security I<Size> should be at least 1024 bits.

This is a required argument.

=item * Identity

A string that identifies the owner of the key. Typically this is the
combination of the user's name and an email address; for example,

    Foo Bar <foo@bar.com>

The I<Identity> is used to build a User ID packet that is stored in
each of the returned keyblocks.

This is a required argument.

=item * Passphrase

String with which the secret key will be encrypted. When read in from
disk, the key can then only be unlocked using this string.

This is a required argument.

=item * Version

Specifies the key version; defaults to version C<4> keys. You should
only set this to version C<3> if you know why you are doing so (for
backwards compatibility, most likely). Version C<3> keys only support
RSA.

=item * Verbosity

Set to a true value to enable a status display during key generation;
since key generation is a relatively lengthy process, it is helpful
to have an indication that some action is occurring.

I<Verbosity> is 0 by default.

=back

=head1 ERROR HANDLING

If an error occurs in any of the above methods, the method will return
C<undef>. You should then call the method I<errstr> to determine the
source of the error:

    $pgp->errstr

In the case that you do not yet have a I<Crypt::OpenPGP> object (that
is, if an error occurs while creating a I<Crypt::OpenPGP> object),
the error can be obtained as a class method:

    Crypt::OpenPGP->errstr

For example, if you try to decrypt some encrypted text, and you do
not give a passphrase to unlock your secret key:

    my $pt = $pgp->decrypt( Filename => "encrypted_data" )
        or die "Decryption failed: ", $pgp->errstr;

=head1 LICENSE

Crypt::OpenPGP is free software; you may redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR & COPYRIGHT

Except where otherwise noted, Crypt::OpenPGP is Copyright 2001 Benjamin
Trott, ben@rhumba.pair.com. All rights reserved.

=head1 REFERENCES

=over 4

=item 1 RFC2440 - OpenPGP Message Format (1998). http://www.faqs.org/rfcs/rfc2440.html

=back 

=cut
