# $Id: Digest.pm,v 1.3 2001/07/23 07:29:02 btrott Exp $

package Crypt::OpenPGP::Digest;
use strict;

use vars qw( %ALG %ALG_BY_NAME );
%ALG = (
    1 => 'MD5',
    2 => 'SHA1',
);
%ALG_BY_NAME = map { $ALG{$_} => $_ } keys %ALG;

sub new {
    my $class = shift;
    my $alg = shift;
    $alg = $ALG{$alg} || $alg;
    my $pkg = join '::', $class, $alg;
    my $dig = bless { __alg => $alg,
                      __alg_id => $ALG_BY_NAME{$alg} }, $pkg;
    $dig->init(@_);
}

sub init { $_[0] }
sub hash { $_[0]->{md}->($_[1]) }

sub alg {
    return $_[0]->{__alg} if ref($_[0]);
    $ALG{$_[1]} || $_[1];
}

sub alg_id {
    return $_[0]->{__alg_id} if ref($_[0]);
    $ALG_BY_NAME{$_[1]} || $_[1];
}

package Crypt::OpenPGP::Digest::MD5;
use strict;
use base qw( Crypt::OpenPGP::Digest );

sub init {
    my $dig = shift;
    require Digest::MD5;
    $dig->{md} = \&Digest::MD5::md5;
    $dig;
}

package Crypt::OpenPGP::Digest::SHA1;
use strict;
use base qw( Crypt::OpenPGP::Digest );

sub init {
    my $dig = shift;
    require Digest::SHA1;
    $dig->{md} = \&Digest::SHA1::sha1;
    $dig;
}

1;
