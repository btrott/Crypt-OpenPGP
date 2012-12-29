use strict;
use Test::More;

use Crypt::OpenPGP::Digest;
use Config;

my %TESTDATA = (
    1 => [ 16, '6abb1d8ca3f00772440701359a8b2fcf' ],
    2 => [ 20, '37316c7b5cd5c1953ba5d9752c4dabe959c8af53' ],
    3 => [ 20, 'd3d53bea7a263f0086f6a1584c52dfae9e494ce8' ],
    8 => [ 32, 'ba8a15767957c344dd23e38f6d00115cf00a2dfb1b7f28c5a85c863abd951746' ],
    9 => [ 48, '0cee26e732f687308124849c6fd97f39acf5267d45246bd520fdae880e17c9c749ee4bc987642811eefb44e920c764b3' ],
    10 => [ 64, '1849c153b7aaca8eedd1e774191770c94f347ad65be3cb4733406c1d56b17512122bb7cbbdf3e6377aa4c5b3c72433c64f590d321671dc3aa7fc93fdeafebd68' ],
    11 => [ 28, '6576f1956f2ba82934ff3b540eb284168c371b9c66d4c6d7bc2a731a' ],
);

my $data = <<TEXT;
Thus: even Zarathustra
Another-time-loser
Could believe in you
With every goddess a let down
Every idol a bring down
It gets you down
But the search for perfection
Your own predilection
Goes on and on and on and on
TEXT

my %TESTS;
BEGIN {
    %TESTS = %Crypt::OpenPGP::Digest::ALG;

    my $num_tests = 0;
    for my $did (keys %TESTS) {
        my $digest = Crypt::OpenPGP::Digest->new($did);
        if ($digest) {
            $num_tests += 5;
        } else {
            delete $TESTS{$did};
        }
    }

    plan tests => $num_tests;
}

for my $did ( sort { $a <=> $b } keys %TESTS ) {
    diag $TESTS{ $did };
    my $digest = Crypt::OpenPGP::Digest->new( $did );
    isa_ok $digest, 'Crypt::OpenPGP::Digest';
    is $digest->alg, $TESTS{ $did }, 'algorithm name matches';
    is $digest->alg_id, $did, 'algorithm id matches';
    my $hash = $digest->hash( $data );
    is length( $hash ), $TESTDATA{ $did }[0], 'length of digest matches';
    
    SKIP: {
    	if ($TESTS{ $did }eq 'RIPEMD160' && $Config{longsize} == 8 
    			&& $Config{use64bitall} eq 'define' && $Config{longdblsize} == 16) {
    		skip "Skipped due to Crypt::RIPEMD160 bug on 64 bit systems (see rt19138 & rt53323)", 1;
    	}    		
    	is $hash, pack( 'H*', $TESTDATA{$did}[1] ), 'digest data matches';
    }
}
