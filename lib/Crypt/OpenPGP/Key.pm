# $Id: Key.pm,v 1.4 2001/07/26 02:34:52 btrott Exp $

package Crypt::OpenPGP::Key;
use strict;

use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

use vars qw( %ALG %ALG_BY_NAME );
%ALG = (
    1 => 'RSA',
    16 => 'ElGamal',
    17 => 'DSA',
);
%ALG_BY_NAME = map { $ALG{$_} => $_ } keys %ALG;

sub new {
    my $class = shift;
    my $alg = shift;
    $alg = $ALG{$alg} || $alg;
    my $pkg = join '::', $class, $alg;
    eval "use $pkg;";
    return $class->error("Unsupported algorithm '$alg': $@") if $@;
    my @valid = $pkg->all_props;
    my %valid = map { $_ => 1 } @valid;
    my $key = bless { __valid => \%valid, __alg => $alg,
                      __alg_id => $ALG_BY_NAME{$alg} }, $pkg;
    $key->init(@_);
}

sub keygen {
    my $class = shift;
    my $alg = shift;
    $alg = $ALG{$alg} || $alg;
    my $pkg = join '::', __PACKAGE__, 'Public', $alg;
    eval "use $pkg;";
    return $class->error("Unsupported algorithm '$alg': $@") if $@;
    my($pub_data, $sec_data) = $pkg->keygen(@_);
    return $class->error("Key generation failed: " . $class->errstr)
        unless $pub_data && $sec_data;
    my $pub_pkg = join '::', __PACKAGE__, 'Public';
    my $pub = $pub_pkg->new($alg, $pub_data);
    my $sec_pkg = join '::', __PACKAGE__, 'Secret';
    my $sec = $sec_pkg->new($alg, $sec_data);
    ($pub, $sec);
}

sub init { $_[0] }
sub check { 1 }
sub size { 0 }
sub alg { $_[0]->{__alg} }
sub alg_id { $_[0]->{__alg_id} }

sub bytesize { int(($_[0]->size + 7) / 8) }

sub DESTROY { }

use vars qw( $AUTOLOAD );
sub AUTOLOAD {
    my $key = shift;
    (my $meth = $AUTOLOAD) =~ s/.*:://;
    die "Can't call method $meth on Key $key" unless $key->{__valid}{$meth};
    $key->{key_data}->$meth(@_);
}

1;
