# $Id: Makefile.PL,v 1.15 2002/12/10 01:48:09 btrott Exp $

use ExtUtils::MakeMaker qw( prompt WriteMakefile );
use strict;

use Getopt::Long;
my($is_sdk);
GetOptions("sdk", \$is_sdk);

use File::Spec;
use File::Basename qw/dirname/;
use lib File::Spec->catdir(dirname($0), 'inc');

use ExtUtils::AutoInstall (
    -core => [
        'Data::Buffer'     => '0.04',
        'MIME::Base64'     => 0,
        'Math::Pari'       => 0,
        'Compress::Zlib'   => 0,
        'LWP::UserAgent'   => 0,
        'URI::Escape'      => 0,

        'Crypt::DSA'       => 0,
        'Crypt::RSA'       => 0,
    ],

    'PGP2 Compatibility (Minimum)' => [
        -default           => $is_sdk,
        'Crypt::IDEA'      => 0,
        'Digest::MD5'      => 0,
    ],

    'PGP5 Compatibility (Minimum)' => [
        -default           => $is_sdk,
        'Crypt::DES_EDE3'  => 0,
        'Digest::SHA1'     => 0,
    ],

    'GnuPG Compatibility (Minimum)' => [
        -default           => $is_sdk,
        'Crypt::Rijndael'  => 0,
        'Crypt::CAST5_PP'  => 0,
        'Crypt::RIPEMD160' => 0,
    ],

    'Support for all ciphers' => [
        -default           => $is_sdk,
        'Crypt::IDEA'      => 0,
        'Crypt::DES_EDE3'  => 0,
        'Crypt::CAST5_PP'  => 0,
        'Crypt::Blowfish'  => 0,
        'Crypt::Twofish'   => '2.00',
        'Crypt::Rijndael'  => 0,
    ],

    'Support for all digests' => [
        -default           => $is_sdk,
        'Digest::MD5'      => 0,
        'Digest::SHA1'     => 0,
        'Crypt::RIPEMD160' => 0,
    ],
);

WriteMakefile(
    AUTHOR       => 'Benjamin Trott <cpan@stupidfool.org>',
    ABSTRACT     => 'Pure-Perl OpenPGP-compatible PGP implementation',
    NAME         => 'Crypt::OpenPGP',
    VERSION_FROM => 'lib/Crypt/OpenPGP.pm',
    DISTNAME     => 'Crypt-OpenPGP',
);
