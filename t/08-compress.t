# $Id: 08-compress.t,v 1.1 2001/08/09 19:08:01 btrott Exp $

use Test;
use Crypt::OpenPGP::Compressed;
use strict;

my $data = <<TEXT;
I never wanted 2 be your weekend lover
I only wanted 2 be some kind of friend
Baby I could never steal u from another
it's such a shame our friendship had 2 end
TEXT

my %TESTS;
BEGIN {
    %TESTS = %Crypt::OpenPGP::Compressed::ALG;
    my $num_tests = 5 * scalar keys %TESTS;
    plan tests => $num_tests;
}

for my $cid (sort { $a <=> $b } keys %TESTS) {
    my $cdata = Crypt::OpenPGP::Compressed->new(
                          Data => $data,
                          Alg  => $cid
                );
    ok($cdata);
    ok($cdata->alg, $TESTS{$cid});
    ok($cdata->alg_id, $cid);
    my $decomp = $cdata->decompress;
    ok(length($decomp), length($data));
    ok($decomp, $data);
}
