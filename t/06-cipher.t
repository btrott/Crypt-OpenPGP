use strict;
use Test::More;

use Crypt::OpenPGP::Cipher;

my $KEY = pack "H64", ( "0123456789ABCDEF" x 8 );
my $PASS = pack "H16", ( "0123456789ABCDEF" );

my $data = <<'TEXT';
I 'T' them, 24:7, all year long
purgatory's circle, drowning here, someone will always say yes
funny place for the social, for the insects to start caring
just an ambulance at the bottom of a cliff
in these plagued streets of pity you can buy anything
for $200 anyone can conceive a God on video
TEXT

my %TESTS;
BEGIN {
    %TESTS = %Crypt::OpenPGP::Cipher::ALG;

    my $num_tests = 0;
    for my $cid ( keys %TESTS ) {
        my $cipher = Crypt::OpenPGP::Cipher->new( $cid );
        if ($cipher) {
            $num_tests += 7;
        } else {
            delete $TESTS{$cid};
        }
    }

    plan tests => $num_tests;
}

for my $cid ( keys %TESTS ) {
    diag $TESTS{ $cid };

    my $ciph1 = Crypt::OpenPGP::Cipher->new( $cid, $KEY );
    isa_ok $ciph1, 'Crypt::OpenPGP::Cipher';
    is $ciph1->alg, $TESTS{ $cid }, 'alg matches';
    is $ciph1->alg_id, $cid, 'alg_id matches';
    is $ciph1->blocksize, $ciph1->{cipher}{cipher}->blocksize,
        'reported blocksize is correct';

    my $ciph2 = Crypt::OpenPGP::Cipher->new( $cid, $KEY );
    isa_ok $ciph2, 'Crypt::OpenPGP::Cipher';

    my( $enc, $dec );
    my $check_bytes = _checkbytes();
    $enc = $ciph1->encrypt( $check_bytes);
    $dec = $ciph2->decrypt( $enc );
    is $dec, $check_bytes, 'decrypting encrypted check-bytes yields original';

    is $ciph2->decrypt( $ciph1->encrypt( $data ) ), $data,
        'decrypting encrypted data yields original';
}

sub _checkbytes {
    my($check1, $check2) = (chr int rand 255, chr int rand 255);
    "$check1$check2$check1$check2" . "\0\0\0\0";
}