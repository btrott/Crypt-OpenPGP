# $Id: S2k.pm,v 1.4 2001/07/26 00:49:02 btrott Exp $

package Crypt::OpenPGP::S2k;
use strict;

use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::Digest;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

use vars qw( %TYPES );
%TYPES = (
    0 => 'Simple',
    1 => 'Salted',
    3 => 'Salt_Iter',
);

sub new {
    my $class = shift;
    my $type = shift;
    my $buffer = shift;
    $type = $TYPES{ $type } || $type;
    if (!$type && $buffer) {
        my $id = $buffer->get_int8;
        $type = $TYPES{$id};
    }
    return $class->error("Invalid type of S2k") unless $type;
    my $pkg = join '::', __PACKAGE__, $type;
    my $s2k = bless { }, $pkg;
    $s2k->init($buffer);
}

sub init { $_[0] }
sub generate {
    my $s2k = shift;
    my($passphrase, $key_len) = @_;
    my($material, $pass) = ('', 0);
    my $hash = $s2k->{hash};
    while (length($material) < $key_len) {
        my $pad = '' . chr(0) x $pass;
        $material .= $s2k->s2k($passphrase, $pad);
        $pass++;
    }
    substr($material, 0, $key_len);
}
sub set_hash {
    my $s2k = shift;
    my($hash_alg) = @_;
    $s2k->{hash} = ref($hash_alg) ? $hash_alg :
        Crypt::OpenPGP::Digest->new($hash_alg);
}

package Crypt::OpenPGP::S2k::Simple;
use base qw( Crypt::OpenPGP::S2k );

use Crypt::OpenPGP::Constants qw( DEFAULT_DIGEST );

sub init {
    my $s2k = shift;
    my($buf) = @_;
    if ($buf) {
        $s2k->{hash_alg} = $buf->get_int8;
    }
    else {
        $s2k->{hash_alg} = DEFAULT_DIGEST;
    }
    if ($s2k->{hash_alg}) {
        $s2k->{hash} = Crypt::OpenPGP::Digest->new($s2k->{hash_alg});
    }
    $s2k;
}

sub s2k { $_[0]->{hash}->hash($_[2] . $_[1]) }

package Crypt::OpenPGP::S2k::Salted;
use base qw( Crypt::OpenPGP::S2k );

use Crypt::OpenPGP::Constants qw( DEFAULT_DIGEST );

sub init {
    my $s2k = shift;
    my($buf) = @_;
    if ($buf) {
        $s2k->{hash_alg} = $buf->get_int8;
        $s2k->{salt} = $buf->get_bytes(8);
    }
    else {
        $s2k->{hash_alg} = DEFAULT_DIGEST;
        require Crypt::Random;
        $s2k->{salt} = Crypt::Random::makerandom_octet( Length => 8 );
    }
    if ($s2k->{hash_alg}) {
        $s2k->{hash} = Crypt::OpenPGP::Digest->new($s2k->{hash_alg});
    }
    $s2k;
}

sub s2k { $_[0]->{hash}->hash($_[2] . $_[1] . $_[0]->{salt}) }

package Crypt::OpenPGP::S2k::Salt_Iter;
use base qw( Crypt::OpenPGP::S2k );

use Crypt::OpenPGP::Constants qw( DEFAULT_DIGEST );

sub init {
    my $s2k = shift;
    my($buf) = @_;
    if ($buf) {
        $s2k->{hash_alg} = $buf->get_int8;
        $s2k->{salt} = $buf->get_bytes(8);
        $s2k->{count} = $buf->get_int8;
    }
    else {
        $s2k->{hash_alg} = DEFAULT_DIGEST;
        require Crypt::Random;
        $s2k->{salt} = Crypt::Random::makerandom_octet( Length => 8 );
        $s2k->{count} = 96;
    }
    if ($s2k->{hash_alg}) {
        $s2k->{hash} = Crypt::OpenPGP::Digest->new($s2k->{hash_alg});
    }
    $s2k;
}

sub s2k {
    my $s2k = shift;
    my($pass, $pad) = @_;
    my $salt = $s2k->{salt};
    my $count = (16 + ($s2k->{count} & 15)) << (($s2k->{count} >> 4) + 6);
    my $len = length($pass) + 8;
    if ($count < $len) {
        $count = $len;
    }
    my $res = $pad;
    while ($count > $len) {
        $res .= $salt . $pass;
        $count -= $len;
    }
    if ($count < 8) {
        $res .= substr($salt, 0, $count);
    } else {
        $res .= $salt;
        $count -= 8;
        $res .= substr($pass, 0, $count);
    }
    $s2k->{hash}->hash($res);
}

sub save {
    my $s2k = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->put_int8(3);
    $buf->put_int8($s2k->{hash_alg});
    $buf->put_bytes($s2k->{salt});
    $buf->put_int8($s2k->{count});
    $buf;
}

1;
