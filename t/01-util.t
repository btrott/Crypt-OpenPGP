use strict;
use Test::More tests => 63;

use Math::BigInt;
use Crypt::OpenPGP::Util qw( bin2bigint bigint2bin bitsize mod_exp mod_inverse );

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
    my $n = bin2bigint( $t->[0] );
    my $num = Math::BigInt->new( $t->[1] );
    is $n, $num, 'bin2bigint matches BigInt';
    if ($t->[2]) {
        is bitsize( $num ), $t->[2], 'bitsize for bin2bigint is correct';
        is bitsize( $n ), $t->[2], 'bitsize for BigInt is correct';
    }
    is bigint2bin( $n ), $t->[0], 'bigint2bin gives us original';
    is bigint2bin( $t->[1] ), $t->[0], 'bigint2bin (from string) gives us original';
}
 
my( $n1, $n2, $n3, $n4 ) = map { Math::BigInt->new( $_ ) }
    ( "23098230958", "35", "10980295809854", "5115018827600" );
my $num = mod_exp( $n1, $n2, $n3 );
is $num, $n4, 'mod_exp is correct';

( $n1, $n2, $n3 ) = map { Math::BigInt->new($_) }
    ("34093840983", "23509283509", "7281956166");
$num = mod_inverse( $n1, $n2 );
is $num, $n3, 'mod_inverse gives expected result';
is 1, ( $n1 * $num ) % $n2, 'mod_inverse verified';

for my $bits (190..200) {
	my $val = Crypt::OpenPGP::Util::get_random_bigint($bits);
	my $topbit = Math::BigInt->new("0b1" . ("0" x ($bits-1)));
	$topbit->band($val);
	ok !$topbit->is_zero, "top bit is set for $bits-bit number";
	$val->brsft($bits);
	ok $val->is_zero, "number is exactly $bits bits";
}
