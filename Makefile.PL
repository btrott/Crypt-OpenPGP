# $Id: Makefile.PL,v 1.8 2001/07/29 17:52:56 btrott Exp $

use ExtUtils::MakeMaker qw( prompt WriteMakefile );
use strict;

my %BASE_PREREQS = (
        'Data::Buffer'   => '0.03',
        'MIME::Base64'   => 0,
        'Math::Pari'     => 0,
        'Compress::Zlib' => 0,

        'Crypt::DSA' => 0,
        'Crypt::RSA' => 0,
);

my %prereq = %BASE_PREREQS;

my @cryptmod = (
    [ '3DES' => 'Crypt::DES' ],
    [ 'IDEA' => 'Crypt::IDEA' ],
    [ 'Blowfish' => 'Crypt::Blowfish' ],
    [ 'Twofish' => 'Crypt::Twofish', '2.00' ],
    [ 'Rijndael' => 'Crypt::Rijndael' ],
);

my @dgstmod = (
    [ 'MD5' => 'Digest::MD5' ],
    [ 'SHA-1' => 'Digest::SHA1' ],
    [ 'RIPE-MD/160' => 'Crypt::RIPEMD160' ],
);

my @pkmod = (
    [ 'DSA' => 'Crypt::DSA' ],
    [ 'ElGamal' => '' ],
    [ 'RSA' => 'Crypt::RSA' ],
);

print<<MSG;
This is Crypt::OpenPGP, a pure-Perl implementation of the OpenPGP
standard.

Each of the Crypt::OpenPGP symmetric ciphers depends on a Crypt::
module from the CPAN. You may already have the necessary module(s)
installed, in which you don't need to bother with this step.
Otherwise you'll need to select a cipher to use with Crypt::OpenPGP.
Please choose at least one from the following list (3DES is the
default).

MSG
my $i = 1;
for my $ciph (@cryptmod) {
    printf "    [%d] %s\n", $i++, $ciph->[0];
}
my $c = prompt("\nEnter your choices, separated by spaces:", 1);
print "\n";

for my $id (split /\s+/, $c) {
    next unless $cryptmod[$id-1]->[1];
    $prereq{ $cryptmod[$id-1]->[1] } = $cryptmod[$id-1]->[2] || '0';
}

print<<MSG;
Each of the Crypt::OpenPGP digest algorithms depends on a module
from the CPAN. You may already have the necessary module(s)
installed, in which you don't need to bother with this step.
Otherwise you'll need to select a digest to use with Crypt::OpenPGP.
Please choose at least one from the following list (SHA-1 is the
default).

MSG
my $i = 1;
for my $ciph (@dgstmod) {
    printf "    [%d] %s\n", $i++, $ciph->[0];
}
my $c = prompt("\nEnter your choices, separated by spaces:", 2);
print "\n";

for my $id (split /\s+/, $c) {
    next unless $dgstmod[$id-1]->[1];
    $prereq{ $dgstmod[$id-1]->[1] } = '0';
}

=pod

print<<MSG;

Crypt::OpenPGP also requires at least one public-key implementation;
it may require more, depending on what types of keys you use in
your other PGP applications. Each public-key implementation may
depend on a Crypt:: module from the CPAN. You may already have the
necessary module(s) installed, in which you don't need to bother with
this step. Otherwise you'll need to select a public-key implementation
to use with Crypt::OpenPGP. Please choose at least one from the
following list (DSA and ElGamal are the defaults).

MSG
my $i = 1;
for my $pk (@pkmod) {
    printf "    [%d] %s\n", $i++, $pk->[0];
}
my $c = prompt("\nEnter your choices, separated by spaces:", '1 2');
print "\n";

for my $id (split /\s+/, $c) {
    next unless $pkmod[$id-1]->[1];
    $prereq{ $pkmod[$id-1]->[1] } = '0';
}

=cut

print "\nChecking for required modules\n\n";
my(%todo, $missing);
while (my($k, $v) = each %prereq) {
    unless (check_module($k, $v, \$missing)) {
        $todo{$k} = $v;
    }
}
use Cwd;
my $cwd = cwd();

if (%todo) {
    print <<MSG;
Crypt::OpenPGP depends on several external modules for functionality.
Some of these modules can not be found on your system; they can be
installed automatically for you. To do so will require loading the
CPAN shell, which may require you to be running as root. Answer 'n' to
each of the following questions if you'd rather not install any
needed modules right now; note, however, that you'll still need to
install them to use Crypt::OpenPGP.

MSG

    while (my($k, $v) = each %todo) {
        if (prompt(sprintf("%s%s not installed/out of date. Install (y/n)?",
          $k, $v ? " (ver. $v)" : ""), "y") =~ /^y/) {
            require CPAN; CPAN::Shell->install($k);
            delete $prereq{$k};
            chdir $cwd or die "Can't chdir back to $cwd: $!";
        }
    }
}

print "\n";
WriteMakefile(
    NAME => 'Crypt::OpenPGP',
    DISTNAME => 'Crypt-OpenPGP',
    VERSION_FROM => 'lib/Crypt/OpenPGP.pm',
    AUTHOR => 'Benjamin Trott <ben@rhumba.pair.com>',
    ABSTRACT => 'Pure-Perl OpenPGP-compatible PGP implementation',
    PREREQ_PM    => \%prereq,
);

sub read_yes_or_no {
    my($prompt, $def) = @_;
    my $ans = prompt($prompt, $def);
    $ans =~ /^y/i;
}

sub check_module {
    my($name, $ver, $missing) = @_;
    print substr("$name ............................", 0, 30);
    my $ok = have_mod($name, $ver);
    $$missing++ unless $ok;
    print $ok ? "ok\n" : "** FAILED **\n";
    $ok;
}

sub have_mod {
    my($name, $ver) = @_;
    eval("use $name" . ($ver ? " $ver;" : ";"));
    !$@;
}
