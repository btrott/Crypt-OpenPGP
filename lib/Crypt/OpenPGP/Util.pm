# $Id: Util.pm,v 1.4 2001/07/26 17:49:33 btrott Exp $

package Crypt::OpenPGP::Util;
use strict;

use Math::Pari qw( PARI pari2num floor Mod lift );

use vars qw( @EXPORT_OK @ISA );
use Exporter;
@EXPORT_OK = qw( bitsize bin2mp mp2bin mod_exp mod_inverse );
@ISA = qw( Exporter );

sub bitsize {
    return pari2num(floor(Math::Pari::log($_[0])/Math::Pari::log(2)) + 1);
}

sub bin2mp { Math::Pari::_hex_cvt('0x' . unpack 'H*', $_[0]) }

sub mp2bin {
    my($p) = @_;
    $p = PARI($p);
    my $base = PARI(1) << PARI(4*8);
    my $res = '';
    while ($p != 0) {
        my $r = $p % $base;
        $p = ($p-$r) / $base;
        my $buf = pack 'N', $r;
        if (!$p) {
            $buf = $r >= 16777216 ? $buf :
                   $r >= 65536 ? substr($buf, -3, 3) :
                   $r >= 256   ? substr($buf, -2, 2) :
                                 substr($buf, -1, 1);
        } 
        $res = $buf . $res;
    }
    $res;
}

sub mod_exp {
    my($a, $exp, $n) = @_;
    my $m = Mod($a, $n);
    lift($m ** $exp);
}

sub mod_inverse {
    my($a, $n) = @_;
    my $m = Mod(1, $n);
    lift($m / $a);
}

1;
