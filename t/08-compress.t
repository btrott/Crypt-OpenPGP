use strict;
use Test::More;

use Crypt::OpenPGP::Compressed;

my $data = <<TEXT;
I never wanted 2 be your weekend lover
I only wanted 2 be some kind of friend
Baby I could never steal u from another
it's such a shame our friendship had 2 end
TEXT

my %TESTS;
BEGIN {
    %TESTS = %Crypt::OpenPGP::Compressed::ALG;
    my $num_tests = 4 * scalar keys %TESTS;
    plan tests => $num_tests;
}

for my $cid ( sort { $a <=> $b } keys %TESTS ) {
    my $cdata = Crypt::OpenPGP::Compressed->new(
        Data => $data,
        Alg  => $cid
    );
    isa_ok $cdata, 'Crypt::OpenPGP::Compressed';
    is $cdata->alg, $TESTS{ $cid }, 'alg matches';
    is $cdata->alg_id, $cid, 'alg_id matches';

    my $decomp = $cdata->decompress;
    is $decomp, $data, 'decompressed data matches original';
}
