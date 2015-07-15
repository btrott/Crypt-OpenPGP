#!/usr/bin/env perl

# see https://github.com/btrott/Crypt-OpenPGP/issues/7
use strict;
use warnings;
use Test::More tests => 9;

use_ok 'Crypt::OpenPGP';
 
my $pgp = Crypt::OpenPGP->new();
 
sub enc { $pgp->encrypt( Data => $_[0], Passphrase => 'allo' ) }

sub dec { $pgp->decrypt( Passphrase => 'allo', Data => $_[0] ) }
 
my @good_vals = qw(
    12345600
    1234567891234500
    12345678912345678912345678912300
    1234567891234567891234567891234567891234567891234567891234567800
);
 
my @bad_vals = qw(
    123456700
    12345678912345600
    123456789123456789123456789123400
    12345678912345678912345678912345678912345678912345678912345678900
);
 
my $i = 1;
for my $msg ( @good_vals, @bad_vals ) {
    is dec(enc($msg)), $msg, 'encrypt->decrypt roudtrip is ok ' . $i++;
}
