# $Id: 06-cipher.t,v 1.1 2001/07/27 22:29:52 btrott Exp $

use Test;
use Crypt::OpenPGP::Cipher;
use strict;

my $KEY = pack "H64", ("0123456789ABCDEF" x 8);
my $PASS = pack "H16", ("0123456789ABCDEF");

my %TESTS;
BEGIN {
    %TESTS = %Crypt::OpenPGP::Cipher::ALG;

    my $num_tests = 0;
    for my $cid (keys %TESTS) {
        my $cipher = Crypt::OpenPGP::Cipher->new($cid);
        if ($cipher) {
            $num_tests += 4;
        } else {
            delete $TESTS{$cid};
        }
    }

    plan tests => $num_tests;
}

for my $cid (sort { $a <=> $b } keys %TESTS) {
    my $ciph1 = Crypt::OpenPGP::Cipher->new($cid, $KEY);
    my $ciph2 = Crypt::OpenPGP::Cipher->new($cid, $KEY);
    ok($ciph1);
    ok($ciph2);
    my($enc, $dec);
    $enc = $ciph1->encrypt(_checkbytes());
    $dec = $ciph2->decrypt($enc);
    ok(vec($dec, 0, 8) == vec($dec, 2, 8));
    ok(vec($dec, 1, 8) == vec($dec, 3, 8));
}

sub _checkbytes {
    my($check1, $check2) = (chr int rand 255, chr int rand 255);
    "$check1$check2$check1$check2" . "\0\0\0\0";
}
