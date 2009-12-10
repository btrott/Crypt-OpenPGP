use strict;
use Test::More tests => 13;

use List::Util qw( max );

use_ok 'Crypt::OpenPGP::Armour';

my $obj = "FOO OBJECT";
my %headers = ( foo => 'bar', baz => 'quux' );

{
    # Test with a short input string.

    my $data = "foo bar bar";
    my $armoured = Crypt::OpenPGP::Armour->armour(
        Data    => $data,
        Object  => $obj,
        Headers => \%headers
    );
    ok $armoured, 'armoured text is produced';

    my $max_len = max map { length } split /\n/, $armoured;
    cmp_ok $max_len, '<=', 64, 'max line length is <= 64 characters';

    my $ref = Crypt::OpenPGP::Armour->unarmour( $armoured );
    is $ref->{Data}, $data, 'unarmour produces original text';
    is $ref->{Object}, "PGP $obj", 'Object is defined properly';
    is_deeply $ref->{Headers}, {
        foo     => $headers{foo},
        baz     => $headers{baz},
        Version => Crypt::OpenPGP->version_string,
    }, 'Headers contains our headers, plus Version';
}

{
    # Test with a longer input string.

    my $data = "foobarbaz" x 50;
    my $armoured = Crypt::OpenPGP::Armour->armour(
        Data    => $data,
        Object  => $obj,
        Headers => \%headers
    );
    ok $armoured, 'armoured text is produced';

    my $max_len = max map { length } split /\n/, $armoured;
    cmp_ok $max_len, '<=', 64, 'max line length is <= 64 characters';

    my $ref = Crypt::OpenPGP::Armour->unarmour( $armoured );
    is $ref->{Data}, $data, 'unarmour produces original text';
    is $ref->{Object}, "PGP $obj", 'Object is defined properly';
    is_deeply $ref->{Headers}, {
        foo     => $headers{foo},
        baz     => $headers{baz},
        Version => Crypt::OpenPGP->version_string,
    }, 'Headers contains our headers, plus Version';
}

{
    my $data = "foobarbaz" x 50;

    # Test that we get rid of \r (\cM) characters from armoured text
    # when calling unarmour.
    my $armoured = Crypt::OpenPGP::Armour->armour(
        Data    => $data,
        Object  => $obj,
        Headers => \%headers
    );
    ok $armoured, 'armoured text is produced';

    $armoured = join "\r\n", split /\n/, $armoured;
    my $ref = Crypt::OpenPGP::Armour->unarmour( $armoured );
    is $data, $ref->{Data}, 'unarmour discards \r characters';
}