# $Id: SessionKey.pm,v 1.10 2001/07/27 19:39:33 btrott Exp $

package Crypt::OpenPGP::SessionKey;
use strict;

use Crypt::OpenPGP::Constants qw( DEFAULT_CIPHER );
use Crypt::OpenPGP::Key::Public;
use Crypt::OpenPGP::Util qw( mp2bin bin2mp );
use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub key_id { $_[0]->{key_id} }

sub new {
    my $class = shift;
    my $key = bless { }, $class;
    $key->init(@_);
}

sub init {
    my $key = shift;
    my %param = @_;
    $key->{version} = 3;
    if ((my $cert = $param{Key}) && (my $sym_key = $param{SymKey})) {
        my $alg = $param{Cipher} || DEFAULT_CIPHER;
        my $keysize = Crypt::OpenPGP::Cipher->new($alg)->keysize;
        $sym_key = substr $sym_key, 0, $keysize;
        my $pk = $cert->key->public_key;
        my $enc = $key->_encode($sym_key, $alg, $pk->bytesize) or
            return (ref $key)->error("Encoding symkey failed: " . $key->errstr);
        $key->{key_id} = $cert->key_id;
        $key->{C} = $pk->encrypt($enc) or
            return (ref $key)->error("Encryption failed: " . $pk->errstr);
        $key->{pk_alg} = $pk->alg_id;
    }
    $key;
}

sub parse {
    my $class = shift;
    my($buf) = @_;
    my $key = $class->new;
    $key->{version} = $buf->get_int8;
    return $class->error("Unsupported version ($key->{version})")
        unless $key->{version} == 2 || $key->{version} == 3;
    $key->{key_id} = $buf->get_bytes(8);
    $key->{pk_alg} = $buf->get_int8;
    my $pk = Crypt::OpenPGP::Key::Public->new($key->{pk_alg});
    my @props = $pk->crypt_props;
    for my $e (@props) {
        $key->{C}{$e} = $buf->get_mp_int;
    }
    $key;
}

sub save {
    my $key = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->put_int8($key->{version});
    $buf->put_bytes($key->{key_id}, 8);
    $buf->put_int8($key->{pk_alg});
    my $c = $key->{C};
    for my $mp (values %$c) {
        $buf->put_mp_int($mp);
    }
    $buf->bytes;
}

sub decrypt {
    my $key = shift;
    my($sk) = @_;
    return $key->error("Invalid secret key ID")
        unless $key->key_id eq $sk->key_id;
    my($sym_key, $alg) = __PACKAGE__->_decode($sk->key->decrypt($key->{C}))
        or return $key->error("Session key decryption failed: " .
            __PACKAGE__->errstr);
    ($sym_key, $alg);
}

sub _encode {
    my $class = shift;
    require Crypt::Random;
    my($sym_key, $sym_alg, $size) = @_;
    my $padlen = $size - length($sym_key) - 2 - 2 - 2;
    my $pad = Crypt::Random::makerandom_octet( Length => $padlen,
                                               Skip => chr(0) );
    bin2mp(pack 'na*na*n', 2, $pad, $sym_alg, $sym_key,
        unpack('%16C*', $sym_key));
}

sub _decode {
    my $class = shift;
    my($n) = @_;
    my $ser = mp2bin($n);
    return $class->error("Encoded data must start with 2")
        unless unpack('C', $ser) == 2;
    my $csum = unpack 'n', substr $ser, -2, 2, '';
    my($pad, $sym_key) = split /\0/, $ser, 2;
    my $sym_alg = ord substr $sym_key, 0, 1, '';
    return $class->error("Encoded data has bad checksum")
        unless unpack('%16C*', $sym_key) == $csum;
    ($sym_key, $sym_alg);
}

1;
