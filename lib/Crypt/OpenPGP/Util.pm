# $Id: Util.pm,v 1.5 2001/07/29 03:30:11 btrott Exp $

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
__END__

=head1 NAME

Crypt::OpenPGP::Util - Miscellaneous utility functions

=head1 SYNOPSIS

    use Crypt::OpenPGP::Util qw( func1 func2 ... );

=head1 DESCRIPTION

I<Crypt::OpenPGP::Util> contains a set of exportable utility functions
used through the I<Crypt::OpenPGP> set of libraries.

=head2 bitsize($n)

Returns the number of bits in the I<Math::Pari> integer object
I<$n>.

=head2 bin2mp($string)

Given a string I<$string> of any length, treats the string as a
base-256 representation of an integer, and returns that integer,
a I<Math::Pari> object.

=head2 mp2bin($int)

Given a biginteger I<$int> (a I<Math::Pari> object), linearizes
the integer into an octet string, and returns the octet string.

=head2 mod_exp($a, $exp, $n)

Computes $a ^ $exp mod $n and returns the value. The calculations
are done using I<Math::Pari>, and the return value is a I<Math::Pari>
object.

=head2 mod_inverse($a, $n)

Computes the multiplicative inverse of $a mod $n and returns the
value. The calculations are done using I<Math::Pari>, and the
return value is a I<Math::Pari> object.

=head1 AUTHOR & COPYRIGHTS

Please see the Crypt::OpenPGP manpage for author, copyright, and
license information.

=cut
