use strict;
use Test::More;

eval "use Crypt::OpenPGP::CFB; use Crypt::DES_EDE3";
if ( $@ ) {
    plan skip_all => 'test requires DES-EDE3 installed';
}

plan tests => 5;

my $KEY = pack "H64", ( "0123456789ABCDEF" x 4 );

my( $des1, $des2 );

$des1 = Crypt::DES_EDE3->new( $KEY );
isa_ok $des1, 'Crypt::DES_EDE3';
is $des1->keysize, 24, 'keysize is 24 bytes';

$des2 = Crypt::DES_EDE3->new( $KEY );
isa_ok $des2, 'Crypt::DES_EDE3';

my( $enc, $dec );
my $check_bytes = _checkbytes();
$enc = $des1->encrypt( $check_bytes );
ok $enc, 'ciphertext is defined';
$dec = $des2->decrypt( $enc );
is $dec, $check_bytes, 'decrypted matches plaintext';

sub _checkbytes {
    my( $check1, $check2 ) = ( chr int rand 255, chr int rand 255 );
    return "$check1$check2$check1$check2\0\0\0\0";
}