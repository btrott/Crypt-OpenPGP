# $Id: 03-3des.t,v 1.2 2001/07/24 19:21:48 btrott Exp $

use strict;

use Test;

BEGIN {
    eval "use Crypt::OpenPGP::CFB; use Crypt::DES_EDE3;";
    if ($@) {
        print "1..0 skipping\n";
        exit;
    }

    plan tests => 7;
}

my $KEY = pack "H64", ("0123456789ABCDEF" x 4);

my($des1, $des2);

$des1 = Crypt::DES_EDE3->new($KEY);
ok($des1);

$des2 = Crypt::DES_EDE3->new($KEY);
ok($des2);

my($enc, $dec);
$enc = $des1->encrypt( _checkbytes() );
ok($enc);
$dec = $des2->decrypt($enc);
ok($dec);

ok( vec($dec, 0, 8) == vec($dec, 2, 8) );
ok( vec($dec, 1, 8) == vec($dec, 3, 8) );
ok( vec($dec, 5, 8) == 0 );

sub _checkbytes {
    my($check1, $check2) = (chr int rand 255, chr int rand 255);
    "$check1$check2$check1$check2\0\0\0\0";
}
