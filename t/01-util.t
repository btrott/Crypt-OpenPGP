# $Id: 01-util.t,v 1.3 2001/07/29 03:28:26 btrott Exp $

use strict;

use Test;
use Math::Pari;
use Crypt::OpenPGP::Util qw( bin2mp mp2bin bitsize mod_exp mod_inverse );

BEGIN { plan tests => 33 }

use vars qw( @TESTS );
@TESTS = (
    [ 'abcdefghijklmnopqrstuvwxyz-0123456789',
      '48431489725691895261376655659836964813311343892465012587212197286379595482592365885470777',
      295 ],

    [ 'abcd',
      '1633837924',
       31 ],

    [ '',
      0 ],

    [ 'Just another Perl hacker,',
      '467385418330892203511763656169504687570145361182972059152940',
      199 ],

    [ 'J',
      74,
      7 ],

    [ 'Ju',
      19061,
      15 ],

    [ 'Jus',
      4879731,
      23 ],

    [ 'Just',
      1249211252,
      31 ],
);

for my $t (@TESTS) {
    my $n = bin2mp($t->[0]);
    my $num = PARI($t->[1]);
    ok($n, $num);
    if ($t->[2]) {
        ok(bitsize($num), $t->[2]);
        ok(bitsize($n), $t->[2]);
    }
    ok(mp2bin($n), $t->[0]);
}
 
my($n1, $n2, $n3, $n4);
($n1, $n2, $n3, $n4) = map PARI($_), ("23098230958", "35", "10980295809854", "5115018827600");
my $num = mod_exp($n1, $n2, $n3);
ok($num, $n4);

($n1, $n2, $n3) = map PARI($_), ("34093840983", "23509283509", "7281956166");
$num = mod_inverse($n1, $n2);
ok($num, $n3);
ok(1, ($n1*$num)%$n2);
