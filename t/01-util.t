# $Id: 01-util.t,v 1.2 2001/07/25 00:36:21 btrott Exp $

use strict;

use Test;
use Math::Pari;
use Crypt::OpenPGP::Util qw( bin2mp mp2bin bitsize );

BEGIN { plan tests => 30 }

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
 
