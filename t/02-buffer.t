use strict;
use Test::More tests => 6;

use Math::BigInt;
use Crypt::OpenPGP::Buffer;

my @num = map { Math::BigInt->new( $_ ) } qw( 34093840983 99999999999999999999 1 );

for my $n ( @num ) {
    my $buffer = Crypt::OpenPGP::Buffer->new;
    isa_ok $buffer, 'Crypt::OpenPGP::Buffer';
    $buffer->put_mp_int( $n );
    is $buffer->get_mp_int, $n, 'get_mp_int gives us back what we put in';
}
