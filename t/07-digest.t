# $Id: 07-digest.t,v 1.1 2001/07/29 09:46:50 btrott Exp $

use Test;
use Crypt::OpenPGP::Digest;
use strict;

my %TESTDATA = (
    1 => [ 16, 'b39a3a792064c8d0e8ed98d3f9096fab' ],
    2 => [ 20, '5eba31e3a9be283ab243fb018952febee1cd790d' ],
    3 => [ 20, '1b710d273e1c69119be855108e692f931178d67a' ],
);

my $data = <<TEXT;
Thus: even Zarathustra
Another-time-loser
Could believe in you
With every goddess a let down
Every idol a bring down
It gets you down
But the search for perfection
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
