# $Id: 04-armour.t,v 1.2 2001/07/26 17:53:04 btrott Exp $

use Test;
use Crypt::OpenPGP::Armour;
use Crypt::OpenPGP;

BEGIN { plan tests => 16 }

my $data = "foo bar bar";
my $obj = "FOO OBJECT";
my %headers = ( foo => 'bar', baz => 'quux' );

my $armoured = Crypt::OpenPGP::Armour->armour(
                       Data => $data,
                       Object => $obj,
                       Headers => \%headers
                );
ok($armoured);
my @lines = split /\n/, $armoured;
my $max_len = 0;
for (@lines) {
    $max_len = length($_) if length($_) > $max_len;
}
ok($max_len <= 64);

my $ref = Crypt::OpenPGP::Armour->unarmour($armoured);

ok($data eq $ref->{Data});
ok("PGP $obj" eq $ref->{Object});
ok(keys %{ $ref->{Headers} }, 3);
ok($headers{foo}, $ref->{Headers}->{foo});
ok($headers{baz}, $ref->{Headers}->{baz});
ok($ref->{Headers}->{Version}, Crypt::OpenPGP->version_string);


$data = "foobarbaz" x 50;

$armoured = Crypt::OpenPGP::Armour->armour(
                       Data => $data,
                       Object => $obj,
                       Headers => \%headers
                );
ok($armoured);
@lines = split /\n/, $armoured;
$max_len = 0;
for (@lines) {
    $max_len = length($_) if length($_) > $max_len;
}
ok($max_len <= 64);

$ref = Crypt::OpenPGP::Armour->unarmour($armoured);

ok($data eq $ref->{Data});
ok("PGP $obj" eq $ref->{Object});
ok(keys %{ $ref->{Headers} }, 3);
ok($headers{foo}, $ref->{Headers}->{foo});
ok($headers{baz}, $ref->{Headers}->{baz});
ok($ref->{Headers}->{Version}, Crypt::OpenPGP->version_string);
