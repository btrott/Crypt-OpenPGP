# $Id: Ciphertext.pm,v 1.7 2001/07/25 22:35:24 btrott Exp $

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
        my $pad = Crypt::Random::makerandom_octet( Length => 8 );
        $pad .= substr $pad, -2, 2;
        $enc->{ciphertext} = $cipher->encrypt($pad);
        $cipher->decrypt(substr $enc->{ciphertext}, 2, 8);   ## resync
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
    my $cipher = Crypt::OpenPGP::Cipher->new($sym_alg, $key);
    my $pt = $cipher->decrypt(substr $enc->{ciphertext}, 0, 10);
    return $enc->error("Bad checksum")
        unless substr($pt, 6, 2) eq substr($pt, 8, 2);
    $cipher->decrypt(substr $enc->{ciphertext}, 10);
}

1;
