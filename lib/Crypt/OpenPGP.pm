# $Id: OpenPGP.pm,v 1.73 2001/09/16 04:48:20 btrott Exp $

package Crypt::OpenPGP;
use strict;

use vars qw( $VERSION );
$VERSION = '0.17';

use Crypt::OpenPGP::Constants qw( DEFAULT_CIPHER );
use Crypt::OpenPGP::KeyRing;
use Crypt::OpenPGP::Plaintext;
use Crypt::OpenPGP::Message;
use Crypt::OpenPGP::PacketFactory;
use Crypt::OpenPGP::Config;

use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

use vars qw( %COMPAT );

{
    my $env = sub {
        my $dir = shift; my @paths;
        if (exists $ENV{$dir}) { for (@_) { push @paths, "$ENV{$dir}/$_" } }
        return @paths ? @paths : ();
    };

    %COMPAT = (
        PGP2 => {
              'sign'    => { Digest => 'MD5', Version => 3 },
              'encrypt' => { Cipher => 'IDEA', Compress => 'ZIP' },
              'keygen'  => { Type => 'RSA', Cipher => 'IDEA',
                             Version => 3, Digest => 'MD5' },
              'PubRing' => [
                     $env->('PGPPATH','pubring.pgp'),
                     $env->('HOME', '.pgp/pubring.pgp'),
              ],
              'SecRing' => [
                     $env->('PGPPATH','secring.pgp'),
                     $env->('HOME', '.pgp/secring.pgp'),
              ],
              'Config'  => [
                     $env->('PGPPATH', 'config.txt'),
                     $env->('HOME', '.pgp/config.txt'),
              ],
        },

        PGP5 => {
              'sign'    => { Digest => 'SHA1', Version => 3 },
              'encrypt' => { Cipher => 'DES3', Compress => 'ZIP' },
              'keygen'  => { Type => 'DSA', Cipher => 'DES3',
                             Version => 4, Digest => 'SHA1' },
              'PubRing' => [
                     $env->('PGPPATH','pubring.pkr'),
                     $env->('HOME', '.pgp/pubring.pkr'),
              ],
              'SecRing' => [
                     $env->('PGPPATH','secring.skr'),
                     $env->('HOME', '.pgp/secring.skr'),
              ],
              'Config'  => [
                     $env->('PGPPATH', 'pgp.cfg'),
                     $env->('HOME', '.pgp/pgp.cfg'),
              ],
        },

        GnuPG => {
              'sign'    => { Digest => 'RIPEMD160', Version => 4 },
              'encrypt' => { Cipher => 'Rijndael', Compress => 'Zlib',
                             MDC => 1 },
              'keygen'  => { Type => 'DSA', Cipher => 'Rijndael',
                             Version => 4, Digest => 'RIPEMD160' },
              'Config'  => [
                     $env->('GNUPGHOME', 'options'),
                     $env->('HOME', '.gnupg/options'),
              ],
              'PubRing' => [
                     $env->('GNUPGHOME', 'pubring.gpg'),
                     $env->('HOME', '.gnupg/pubring.gpg'),
              ],
              'SecRing' => [
                     $env->('GNUPGHOME', 'secring.gpg'),
                     $env->('HOME', '.gnupg/secring.gpg'),
              ],
        },
    );
}

sub version_string { __PACKAGE__ . ' ' . $VERSION }

sub new {
    my $class = shift;
    my $pgp = bless { }, $class;
    $pgp->init(@_);
}

sub _first_exists {
    my($list) = @_;
    for my $f (@$list) {
        next unless $f;
        return $f if -e $f;
    }
}

sub init {
    my $pgp = shift;
    my %param = @_;
    my $cfg_file = delete $param{ConfigFile};
    my $cfg = $pgp->{cfg} = Crypt::OpenPGP::Config->new(%param) or
        return Crypt::OpenPGP::Config->errstr;
    if (!$cfg_file && (my $compat = $cfg->get('Compat'))) {
        $cfg_file = _first_exists($COMPAT{$compat}{Config});
    }
    if ($cfg_file) {
        $cfg->read_config($param{Compat}, $cfg_file);
    }
    for my $s (qw( PubRing SecRing )) {
        unless (defined $cfg->get($s)) {
            my @compats = $param{Compat} ? ($param{Compat}) : keys %COMPAT;
            for my $compat (@compats) {
                my $ring = _first_exists($COMPAT{$compat}{$s});
                $cfg->set($s, $ring), last if $ring;
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
        $data = $pgp->_read_files($file) or return $pgp->error($pgp->errstr);
    }
    unless ($cert = $param{Key}) {
        my $kid = $param{KeyID} or return $pgp->error("No KeyID specified");
        my $ring = Crypt::OpenPGP::KeyRing->new( Filename =>
            $pgp->{cfg}->get('SecRing') );
        my $kb = $ring->find_keyblock_by_keyid(pack 'H*', $kid) or
            return $pgp->error("Could not find secret key with KeyID $kid");
        $cert = $kb->signing_key;
        $cert->uid($kb->primary_uid);
    }
    if ($cert->is_protected) {
        my $pass = $param{Passphrase};
        if (!defined $pass && (my $cb = $param{PassphraseCallback})) {
            $pass = $cb->($cert);
        }
        return $pgp->error("Need passphrase to unlock secret key")
            unless $pass;
        $cert->unlock($pass) or
            return $pgp->error("Secret key unlock failed: " . $cert->errstr);
    }
    my @ptarg = ( Data => $data );
    push @ptarg, ( Filename => $param{Filename} ) if $param{Filename};
    push @ptarg, ( Mode => 't' ) if $param{Clearsign};
    my $pt = Crypt::OpenPGP::Plaintext->new(@ptarg);
    my @sigarg;
    if (my $hash_alg = $param{Digest}) {
        my $dgst = Crypt::OpenPGP::Digest->new($hash_alg) or
            return $pgp->error( Crypt::OpenPGP::Digest->errstr );
        @sigarg = ( Digest => $dgst->alg_id );
    }
    push @sigarg, (Type => 0x01) if $param{Clearsign};
    my $sig = Crypt::OpenPGP::Signature->new(
                          Data => $pt,
                          Key  => $cert,
                          Version => $param{Version},
                          @sigarg,
                 );
    if ($param{Clearsign}) {
        $param{Armour} = $param{Detach} = 1;
    }
    my $sig_data = Crypt::OpenPGP::PacketFactory->save($sig,
        $param{Detach} ? () : ($pt));
    if ($param{Armour}) {
        require Crypt::OpenPGP::Armour;
        $sig_data = Crypt::OpenPGP::Armour->armour(
                          Data => $sig_data,
                          Object => ($param{Detach} ? 'SIGNATURE' : 'MESSAGE'),
                 ) or return $pgp->error( Crypt::OpenPGP::Armour->errstr );
    }
    if ($param{Clearsign}) {
        require Crypt::OpenPGP::Util;
        my $hash = Crypt::OpenPGP::Digest->alg($sig->{hash_alg});
        my $data = Crypt::OpenPGP::Util::dash_escape($pt->data);
        $data .= "\n" unless $data =~ /\n$/;
        $sig_data = "-----BEGIN PGP SIGNED MESSAGE-----\n" .
                    ($hash eq 'MD5' ? '' : "Hash: $hash\n") .
                    "\n" .
                    $data .
                    $sig_data;
    }
    $sig_data;
}

sub verify {
    my $pgp = shift;
    my %param = @_;
    my($data, $sig);
    require Crypt::OpenPGP::Signature;
    $param{Signature} or $param{SigFile} or
            return $pgp->error("Need Signature or SigFile to verify");
    my %arg = $param{Signature} ? (Data => $param{Signature}) :
                                  (Filename => $param{SigFile});
    my $msg = Crypt::OpenPGP::Message->new( %arg ) or
        return $pgp->error("Reading signature failed: " .
            Crypt::OpenPGP::Message->errstr);
    my @pieces = $msg->pieces;
    if (ref($pieces[0]) eq 'Crypt::OpenPGP::Compressed') {
        $data = $pieces[0]->decompress or
            return $pgp->error("Decompression error: " . $pieces[0]->errstr);
        $msg = Crypt::OpenPGP::Message->new( Data => $data ) or
            return $pgp->error("Reading decompressed data failed: " .
                Crypt::OpenPGP::Message->errstr);
        @pieces = $msg->pieces;
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
    my($cert, $kb);
    unless ($cert = $param{Key}) {
        my $key_id = $sig->key_id;
        my $ring = Crypt::OpenPGP::KeyRing->new( Filename =>
            $pgp->{cfg}->get('PubRing') );
        $kb = $ring->find_keyblock_by_keyid($key_id) or
            return $pgp->error("Could not find public key with KeyID " .
                unpack('H*', $key_id));
        $cert = $kb->signing_key;
    }
    my $dgst = $sig->hash_data($data) or
        return $pgp->error( $sig->errstr );
    $cert->key->public_key->verify($sig, $dgst) ?
        ($kb && $kb->primary_uid ? $kb->primary_uid : 1) : 0;
}

sub encrypt {
    my $pgp = shift;
    my %param = @_;
    $pgp->_merge_compat(\%param, 'encrypt') or
        return $pgp->error( $pgp->errstr );
    my($data);
    require Crypt::OpenPGP::Cipher;
    require Crypt::OpenPGP::Ciphertext;
    unless ($data = $param{Data}) {
        my $file = $param{Filename} or
            return $pgp->error("Need either 'Data' or 'Filename' to encrypt");
        $data = $pgp->_read_files($file) or return $pgp->error($pgp->errstr);
    }
    my $ptdata;
    if ($param{SignKeyID}) {
        $ptdata = $pgp->sign(
                         Data       => $data,
                         KeyID      => $param{SignKeyID},
                         Compat     => $param{Compat},
                         Passphrase => $param{SignPassphrase},
                         PassphraseCallback => $param{SignPassphraseCallback},
                  );
    } else {
        my $pt = Crypt::OpenPGP::Plaintext->new( Data => $data,
                      $param{Filename} ? (Filename => $param{Filename}) : () );
        $ptdata = Crypt::OpenPGP::PacketFactory->save($pt);
    }
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
    my(@sym_keys);
    if ($param{Recipients} && !ref($param{Recipients})) {
        $param{Recipients} = [ $param{Recipients} ];
    }
    if (my $kid = delete $param{KeyID}) {
        my @kid = ref $kid eq 'ARRAY' ? @$kid : $kid;
        push @{ $param{Recipients} }, @kid;
    }
    if ($param{Key} || $param{Recipients}) {
        require Crypt::OpenPGP::SessionKey;
        my @keys;
        if (my $recips = $param{Recipients}) {
            my @recips = ref $recips eq 'ARRAY' ? @$recips : $recips;
            my $ring = Crypt::OpenPGP::KeyRing->new( Filename =>
                $pgp->{cfg}->get('PubRing') );
            my %seen;
            for my $r (@recips) {
                my($lr, @kb) = (length($r));
                if (($lr == 8 || $lr == 16) && $r !~ /[^\da-fA-F]/) {
                    @kb = $ring->find_keyblock_by_keyid(pack 'H*', $r);
                } else {
                    @kb = $ring->find_keyblock_by_uid($r);
                }
                for my $kb (@kb) {
                    next unless my $cert = $kb->encrypting_key;
                    next if $seen{ $cert->key_id }++;
                    $cert->uid($kb->primary_uid);
                    push @keys, $cert;
                }
            }
            if (my $cb = $param{RecipientsCallback}) {
                @keys = @{ $cb->(\@keys) };
            }
        }
        if ($param{Key}) {
            push @keys, ref $param{Key} eq 'ARRAY' ? @{$param{Key}} :
                                                       $param{Key};
        }
        return $pgp->error("No known recipients for encryption")
            unless @keys;
        for my $key (@keys) {
            push @sym_keys, Crypt::OpenPGP::SessionKey->new(
                                Key    => $key,
                                SymKey => $key_data,
                                Cipher => $sym_alg,
                          ) or
                return $pgp->error( Crypt::OpenPGP::SessionKey->errstr );
        }
    }
    elsif (my $pass = $param{Passphrase}) {
        require Crypt::OpenPGP::SKSessionKey;
        require Crypt::OpenPGP::S2k;
        my $s2k = Crypt::OpenPGP::S2k->new('Salt_Iter');
        my $keysize = Crypt::OpenPGP::Cipher->new($sym_alg)->keysize;
        $key_data = $s2k->generate($pass, $keysize);
        push @sym_keys, Crypt::OpenPGP::SKSessionKey->new(
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
                        MDC    => $param{MDC},
                        SymKey => $key_data,
                        Data   => $ptdata,
                        Cipher => $sym_alg,
                  );
    my $enc_data = Crypt::OpenPGP::PacketFactory->save(@sym_keys, $enc);
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
    my $wants_verify = wantarray;
    my($data);
    unless ($data = $param{Data}) {
        my $file = $param{Filename} or
            return $pgp->error("Need either 'Data' or 'Filename' to decrypt");
        $data = $pgp->_read_files($file) or return $pgp->error($pgp->errstr);
    }
    my $msg = Crypt::OpenPGP::Message->new( Data => $data ) or
        return $pgp->error("Reading data packets failed: " .
            Crypt::OpenPGP::Message->errstr);
    my @pieces = $msg->pieces;
    return $pgp->error("No packets found in message") unless @pieces;
    while (ref($pieces[0]) eq 'Crypt::OpenPGP::Marker') {
        shift @pieces;
    }
    my($key, $alg);
    if (ref($pieces[0]) eq 'Crypt::OpenPGP::SessionKey') {
        my($sym_key, $cert) = (shift @pieces);
        unless ($cert = $param{Key}) {
            my $ring = Crypt::OpenPGP::KeyRing->new(Filename =>
                $pgp->{cfg}->get('SecRing'));
            my($kb);
            while (ref($sym_key) eq 'Crypt::OpenPGP::SessionKey') {
                if ($kb = $ring->find_keyblock_by_keyid($sym_key->key_id)) {
                    shift @pieces
                        while ref($pieces[0]) eq 'Crypt::OpenPGP::SessionKey';
                    last;
                }
                $sym_key = shift @pieces;
            }
            return $pgp->error("Can't find a secret key to decrypt message")
                unless $kb;
            $cert = $kb->encrypting_key;
            $cert->uid($kb->primary_uid);
        }
        if ($cert->is_protected) {
            my $pass = $param{Passphrase};
            if (!defined $pass && (my $cb = $param{PassphraseCallback})) {
                $pass = $cb->($cert);
            }
            return $pgp->error("Need passphrase to unlock secret key")
                unless $pass;
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
    my $valid;
    $pgp->error("No Signature");
    if (ref($pt) eq 'Crypt::OpenPGP::Compressed') {
        $data = $pt->decompress or
            return $pgp->error("Decompression error: " . $pt->errstr);
        my $msg = Crypt::OpenPGP::Message->new( Data => $data );
        my @pieces = $msg->pieces;
        if (ref($pieces[0]) eq 'Crypt::OpenPGP::OnePassSig' ||
            ref($pieces[0]) eq 'Crypt::OpenPGP::Signature') {
            $pt = $pieces[1];
            if ($wants_verify) {
                $valid = $pgp->verify( Signature => $data );
            }
        } else {
            $pt = $pieces[0];
        }
    }
    $wants_verify ? ($pt->data, $valid) : $pt->data;
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

{
    my @MERGE_CONFIG = qw( Cipher Armour Digest );
    sub _merge_compat {
        my $pgp = shift;
        my($param, $meth) = @_;
        my $compat = $param->{Compat} || $pgp->{cfg}->get('Compat') || return 1;
        my $ref = $COMPAT{$compat}{$meth} or
            return $pgp->error("No settings for Compat class '$compat'");
        for my $arg (keys %$ref) {
            $param->{$arg} = $ref->{$arg} unless exists $param->{$arg};
        }
        for my $key (@MERGE_CONFIG) {
            $param->{$key} = $pgp->{cfg}->get($key)
                unless exists $param->{$key};
        }
        1;
    }
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
                   Recipients => $key_id,
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
                  Compat     => 'PGP2',
                  Filename   => 'foo.pl',
                  Recipients => $key_id,
             );

Because I<PGP2> was specified, the data will automatically be encrypted
using the C<IDEA> cipher, and will be compressed using C<ZIP>.

Here is a list of the current compatibility sets and the algorithms and
formats they support.

=over 4

=item * PGP2

Encryption: symmetric cipher = C<IDEA>, compression = C<ZIP>,
modification detection code (MDC) = C<0>

Signing: digest = C<MD5>, packet format = version 3

=item * PGP5

Encryption: symmetric cipher = C<3DES>, compression = C<ZIP>,
modification detection code (MDC) = C<0>

Signing: digest = C<SHA-1>, packet format = version 3

=item * GnuPG

Encryption: symmetric cipher = C<Rijndael>, compression = C<Zlib>,
modification detection code (MDC) = C<1>

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

=item * Compat

The compatibility mode for this I<Crypt::OpenPGP> object. This value will
propagate down into method calls upon this object, meaning that it will be
applied for all method calls invoked on this object. For example, if you set
I<Compat> here, you do not have to set it again when calling I<encrypt>
or I<sign> (below), unless, of course, you want to set I<Compat> to a
different value for those methods.

I<Compat> influences several factors upon object creation, unless otherwise
overridden in the constructor arguments: if you have a configuration file
for this compatibility mode (eg. F<~/.gnupg/options> for GnuPG), it will
be automatically read in, and I<Crypt::OpenPGP> will set any options
relevant to its execution (symmetric cipher algorithm, etc.); I<PubRing>
and I<SecRing> (below) are set according to the default values for this
compatibility mode (eg. F<~/.gnupg/pubring.gpg for the GnuPG public
keyring).

=item * SecRing

Path to your secret keyring. If unspecified, I<Crypt::OpenPGP> will look
for your keyring in a number of default places.

=item * PubRing

Path to your public keyring. If unspecified, I<Crypt::OpenPGP> will look
for your keyring in a number of default places.

=item * ConfigFile

Path to a PGP/GnuPG config file. If specified, you must also pass in a
value for the I<Compat> parameter, stating what format config file you are
passing in. For example, if you are passing in the path to a GnuPG config
file, you should give a value of C<GnuPG> for the I<Compat> flag.

If you leave I<ConfigFile> unspecified, but you have specified a value for
I<Compat>, I<Crypt::OpenPGP> will try to find your config file, based on
the value of I<Compat> that you pass in (eg. F<~/.gnupg/options> if
I<Compat> is C<GnuPG>).

NOTE: if you do not specify a I<Compat> flag, I<Crypt::OpenPGP> cannot read
any configuration files, even if you I<have> specified a value for the
I<ConfigFile> parameter, because it will not be able to determine the proper
config file format.

=back

=head2 $pgp->encrypt( %args )

Encrypts a block of data. The encryption is actually done with a symmetric
cipher; the key for the symmetric cipher is then encrypted with either
the public key of the recipient or using a passphrase that you enter. The
former case is using public-key cryptography, the latter, standard
symmetric ciphers. In the first case, the session key can only be
unlocked by someone with the corresponding secret key; in the second, it
can only be unlocked by someone who knows the passphrase.

Given the parameter I<SignKeyID> (see below), I<encrypt> will first sign
the message before encrypting it, adding a Signature packet to the
encrypted plaintext.

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

=item * Recipients

The intended recipients of the encrypted message. In other words,
either the key IDs or user IDs of the public keys that should be used
to encrypt the message. Each recipient specified should be either a
key ID--an 8-digit or 16-digit hexadecimal number--or part of a user
ID that can be used to look up the user's public key in your keyring.
Examples:

    8-digit hex key ID: 123ABC45
    16-digit hex key ID: 678DEF90123ABC45
    (Part of) User ID: foo@bar

Note that the 8-digit hex key ID is the last 8 digits of the (long)
16-digit hex key ID.

If you wish to encrypt the message for multiple recipients, the value
of I<Recipients> should be a reference to a list of recipients (as
defined above). For each recipient in the list, the public key will be
looked up in your public keyring, and an encrypted session key packet
will be added to the encrypted message.

This argument is optional; if not provided you should provide the
I<Passphrase> option (below) to perform symmetric-key encryption when
encrypting the session key.

=item * KeyID

A deprecated alias for I<Recipients> (above). There is no need to use
I<KeyID>, as its functionality has been completely subsumed into the
I<Recipients> parameter.

=item * Passphrase

The mechanism to use symmetric-key, or "conventional", encryption,
when encrypting the session key. In other words, this allows you to
use I<Crypt::OpenPGP> for encryption/decryption without using public-key
cryptography; this can be useful in certain circumstances (for example,
when encrypting data locally on disk).

This argument is optional; if not provided you should provide the
I<Recipients> option (above) to perform public-key encryption when
encrypting the session key.

=item * RecipientsCallback

After the list of recipients for a message (as given in I<Recipients>,
above) has been mapped into a set of keys from your public keyring,
you can use I<RecipientsCallback> to review/modify that list of keys.
The value of I<RecipientsCallback> should be a reference to a
subroutine; when invoked that routine will be handed a reference to
an array of I<Crypt::OpenPGP::Certificate> objects. It should then
return a reference to a list of such objects.

This can be useful particularly when supplying user IDs in the list
of I<Recipients> for an encrypted message. Since user IDs are looked
up using partial matches (eg. I<b> could match I<b>, I<abc>, I<bar>,
etc.), one intended recipient may actually turn up multiple keys.
You can use I<RecipientsCallback> to audit that list before actually
encrypting the message:

    my %BAD_KEYS = (
        ABCDEF1234567890 => 1,
        1234567890ABCDEF => 1,
    );
    my $cb = sub {
        my $keys = shift;
        my @return;
        for my $cert (@$keys) {
            push @return, $cert unless $BAD_KEYS{ $cert->key_id_hex };
        }
        \@returns;
    };
    my $ct = $pgp->encrypt( ..., RecipientsCallback => $cb, ... );

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

=item * SignKeyID

If you wish to sign the plaintext message before encrypting it, provide
I<encrypt> with the I<SignKeyID> parameter and give it a key ID with
which the message can be signed. This allows recipients of your message
to verify its validity.

By default messages not signed.

=item * SignPassphrase

The passphrase to unlock the secret key to be used when signing the
message.

If you are signing the message--that is, if you have provided the
I<SignKeyID> parameter--either this argument or I<SignPassphraseCallback>
is required.

=item * SignPassphraseCallback

The callback routine to enable the passphrase being passed in through
some user-defined routine. See the I<PassphraseCallback> parameter for
I<sign>, below.

If you are signing the message--that is, if you have provided the
I<SignKeyID> parameter--either this argument or I<SignPassphrase> is
required.

=item * MDC

When set to a true value, instructs I<encrypt> to use encrypted MDC
(modification detection code) packets instead of standard encrypted
data packets. These are a newer form of encrypted data packets that
are followed by a C<SHA-1> hash of the plaintext data. This prevents
attacks that modify the encrypted text by using a message digest to
detect changes.

By default I<MDC> is set to C<0>, and I<encrypt> generates standard
encrypted data packets. Set it to a true value to turn on MDC packets.
Note that I<MDC> will automatically be turned on if you are using a
I<Compat> mode that is known to support it.

=back

=head2 $pgp->decrypt( %args )

Decrypts a block of ciphertext. The ciphertext should be of the sort
returned from I<encrypt>, in either armoured or non-armoured form.
This is compatible with all other implementations of PGP: the output
of their encryption should serves as the input to this method.

When called in scalar context, returns the plaintext (that is, the
decrypted ciphertext), or C<undef> on failure. When called in list
context, returns a two-element list containing the plaintext and the
result of signature verification (see next paragraph), or the empty
list on failure. Either of the failure conditions listed here indicates
that decryption failed.

If I<decrypt> is called in list context, and the encrypted text
contains a signature over the plaintext, I<decrypt> will attempt to
verify the signature and will return the result of that verification
as the second element in the return list. If you call I<decrypt> in
list context and the ciphertext does I<not> contain a signature, that
second element will be C<undef>, and the I<errstr> will be set to
the string C<No Signature>. The second element in the return list can
have one of three possible values: C<undef>, meaning that either an
error occurred in verifying the signature, I<or> the ciphertext did
not contain a signature; C<0>, meaning that the signature is invalid;
or a true value of either the signer's user ID or C<1>, if the user ID
cannot be determined. Note that these are the same values returned from
I<verify> (below).

For example, to decrypt a message that may contain a signature that you
want verified, you might use code like this:

    my($pt, $validity) = $pgp->decrypt( ... );
    die "Decryption failed: ", $pgp->errstr unless $pt;
    die "Signature verification failed: ", $pgp->errstr
        unless defined $validity || $pgp->errstr ne 'No Signature';

This checks for errors in decryption, as well as errors in signature
verification, excluding the error denoting that the plaintext was
not signed.

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

This argument is optional if your secret key is protected; if not
provided you should supply the I<PassphraseCallback> parameter (below).

=item * PassphraseCallback

A callback routine to allow interactive users (for example) to enter the
passphrase for the specific key being used to decrypt the ciphertext.
This is useful when your ciphertext is encrypted to several recipients,
if you do not necessarily know ahead of time the secret key that will be
used to decrypt it. It is also useful when you wish to provide an
interactive user with some feedback about the key being used to decrypt
the message.

The value of this parameter should be a reference to a subroutine. This
routine will be called when a passphrase is needed from the user, and
it will be given one argument: a I<Crypt::OpenPGP::Certificate> object
representing the secret key. You can use the information in this object
to present details about the key to the user. The callback routine
should return the passphrase, a scalar string.

This argument is optional if your secret key is protected; if not
provided you should supply the I<Passphrase> parameter (above).

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

=item * Clearsign

If true, the signature created on the data is a clear-text signature.
This form of signature displays the clear text of the signed data,
followed by the ASCII-armoured signature on that data. Such a format
is desirable when sending signed messages to groups of users who may
or may not have PGP, because it allows the text of the message to be
readable without special software.

When I<Clearsign> is set to true, I<Armour> and I<Detach> are
automatically turned on, because the signature created is a detached,
armoured signature.

By default I<Clearsign> is false.

=item * KeyID

The ID of the secret key that should be used to sign the message. The
value of the key ID should be specified as a 16-digit hexadecimal number.

This argument is mandatory.

=item * Passphrase

The passphrase to unlock your secret key.

This argument is optional if your secret key is protected; if not
provided you should supply the I<PassphraseCallback> parameter (below).

=item * PassphraseCallback

A callback routine to allow interactive users (for example) to enter the
passphrase for the specific key being used to sign the message. This is
useful when you wish to provide an interactive user with some feedback
about the key being used to sign the message.

The value of this parameter should be a reference to a subroutine. This
routine will be called when a passphrase is needed from the user, and
it will be given one argument: a I<Crypt::OpenPGP::Certificate> object
representing the secret key. You can use the information in this object
to present details about the key to the user. The callback routine
should return the passphrase, a scalar string.

This argument is optional if your secret key is protected; if not
provided you should supply the I<Passphrase> parameter (above).

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

Verifies a digital signature. Returns true for a valid signature, C<0>
for an invalid signature, and C<undef> if an error occurs (in which
case you should call I<errstr> to determine the source of the error).
The 'true' value returned for a successful signature will be, if available,
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

=head1 SAMPLES/TUTORIALS

Take a look at F<bin/pgplet> for an example of usage of I<Crypt::OpenPGP>.
It gives you an example of using the four main major methods (I<encrypt>,
I<sign>, I<decrypt>, and I<verify>), as well as the various parameters to
those methods. It also demonstrates usage of the callback parameters (eg.
I<PassphraseCallback>).

F<bin/pgplet> currently does not have any documentation, but its interface
mirrors that of I<gpg>.

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
