# $Id: 07-digest.t,v 1.2 2002/05/07 04:04:55 btrott Exp $

use Test;
use Crypt::OpenPGP::Digest;
use strict;

my %TESTDATA = (
    1 => [ 16, '6abb1d8ca3f00772440701359a8b2fcf' ],
    2 => [ 20, '37316c7b5cd5c1953ba5d9752c4dabe959c8af53' ],
    3 => [ 20, 'd3d53bea7a263f0086f6a1584c52dfae9e494ce8' ],
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

for my $did (sort { $a <=> $b } keys %TESTS) {
    my $digest = Crypt::OpenPGP::Digest->new($did);
    ok($digest);
    ok($digest->alg, $TESTS{$did});
    ok($digest->alg_id, $did);
    my $hash = $digest->hash($data);
    ok(length($hash), $TESTDATA{$did}[0]);
    ok($hash, pack 'H*', $TESTDATA{$did}[1]);
}
