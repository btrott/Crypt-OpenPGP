# $Id: Constants.pm,v 1.5 2001/07/26 20:55:53 btrott Exp $

package Crypt::OpenPGP::Constants;
use strict;

use vars qw( %CONSTANTS );

%CONSTANTS = (
    'PGP_PKT_PUBKEY_ENC' => 1,
    'PGP_PKT_SIGNATURE'  => 2,
    'PGP_PKT_SYMKEY_ENC' => 3,
    'PGP_PKT_ONEPASS_SIG' => 4,
    'PGP_PKT_SECRET_KEY'  => 5,
    'PGP_PKT_PUBLIC_KEY'  => 6,
    'PGP_PKT_SECRET_SUBKEY' => 7,
    'PGP_PKT_COMPRESSED'    => 8,
    'PGP_PKT_ENCRYPTED'     => 9,
    'PGP_PKT_MARKER'        => 10,
    'PGP_PKT_PLAINTEXT'     => 11,
    'PGP_PKT_RING_TRUST'    => 12,
    'PGP_PKT_USER_ID'       => 13,
    'PGP_PKT_PUBLIC_SUBKEY' => 14,

    'DEFAULT_CIPHER' => 2,
    'DEFAULT_DIGEST' => 2,
    'DEFAULT_COMPRESS' => 1,
);

use vars qw( %TAGS );
my %RULES = (
    '^PGP_PKT' => 'packet',
);

for my $re (keys %RULES) {
    $TAGS{ $RULES{$re} } = [ grep /$re/, keys %CONSTANTS ];
}

sub import {
    my $class = shift;

    my @to_export;
    my @args = @_;
    for my $item (@args) {
        push @to_export,
            $item =~ s/^:// ? @{ $TAGS{$item} } : $item;
    }

    no strict 'refs';
    my $pkg = caller;
    for my $con (@to_export) {
        warn __PACKAGE__, " does not export the constant '$con'"
            unless exists $CONSTANTS{$con};
        *{"${pkg}::$con"} = sub () { $CONSTANTS{$con} }
    }
}

1;
