# $Id: 02-buffer.t,v 1.1 2001/07/24 07:38:03 btrott Exp $

use strict;

use Test;
BEGIN { plan tests => 6 }

use Math::Pari;
use Crypt::OpenPGP::Buffer;

my @num = map PARI($_), qw( 34093840983 99999999999999999999 1 );

    for my $n (@num) {
        my $buffer = Crypt::OpenPGP::Buffer->new;
        ok($buffer);
        $buffer->put_mp_int($n);
        ok($buffer->get_mp_int, $n);
    }
