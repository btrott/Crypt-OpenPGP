# $Id: Cipher.pm,v 1.6 2001/07/21 06:54:27 btrott Exp $

package Crypt::OpenPGP::Cipher;
use strict;

use Crypt::OpenPGP::CFB;

use vars qw( %ALG %ALG_BY_NAME );
%ALG = (
    1 => 'IDEA',
    2 => 'DES3',
    3 => 'CAST5',
    4 => 'Blowfish',
);
%ALG_BY_NAME = map { $ALG{$_} => $_ } keys %ALG;

sub new {
    my $class = shift;
    my $alg = shift;
    $alg = $ALG{$alg} || $alg;
    my $pkg = join '::', $class, $alg;
    my $ciph = bless { __alg => $alg,
                       __alg_id => $ALG_BY_NAME{$alg} }, $pkg;
    $ciph->init(@_);
}

sub init {
    my $ciph = shift;
    my($key, $iv) = @_;
    if ($key) {
        my $class = $ciph->crypt_class;
        eval "use $class;";
        my $c = $class->new(substr $key, 0, $ciph->key_len);
        $ciph->{cipher} = Crypt::OpenPGP::CFB->new($c, $iv);
    }
    $ciph;
}

sub encrypt { $_[0]->{cipher}->encrypt($_[1]) }
sub decrypt { $_[0]->{cipher}->decrypt($_[1]) }

sub alg { $_[0]->{__alg} }
sub alg_id {
    return $_[0]->{__alg_id} if ref($_[0]);
    $ALG_BY_NAME{$_[1]} || $_[1];
}

package Crypt::OpenPGP::Cipher::IDEA;
use strict;
use base qw( Crypt::OpenPGP::Cipher );

*Crypt::IDEA::new = \&IDEA::new;
*Crypt::IDEA::blocksize = \&IDEA::blocksize;
*Crypt::IDEA::encrypt = \&IDEA::encrypt;
*Crypt::IDEA::decrypt = \&IDEA::decrypt;

sub crypt_class { 'Crypt::IDEA' }
sub key_len { 16 }

package Crypt::OpenPGP::Cipher::Blowfish;
use strict;
use base qw( Crypt::OpenPGP::Cipher );

sub crypt_class { 'Crypt::Blowfish' }
sub key_len { 16 }

package Crypt::OpenPGP::Cipher::DES3;
use strict;
use base qw( Crypt::OpenPGP::Cipher );

sub crypt_class { 'Crypt::DES_EDE3' }
sub key_len { 24 }

1;
