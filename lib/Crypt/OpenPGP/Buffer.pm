package Crypt::OpenPGP::Buffer;
use base qw( Data::Buffer );

use Crypt::OpenPGP::Util qw( bin2mp mp2bin bitsize );

sub get_mp_int {
    my $buf = shift;
    my $bits = $buf->get_int16;
    my $bytes = int(($bits + 7) / 8);
    my $off = $buf->{offset};
    $buf->{offset} += $bytes;
    bin2mp($buf->bytes($off, $bytes));
}

sub put_mp_int {
    my $buf = shift;
    my($n) = @_;
    $buf->put_int16(bitsize($n));
    $buf->put_bytes(mp2bin($n));
}

1;
