# $Id: 12-sign.t,v 1.5 2001/08/11 07:46:46 btrott Exp $

use Test;
use Crypt::OpenPGP;
use strict;

BEGIN { plan tests => 17 }

use vars qw( $SAMPLES );
unshift @INC, 't/';
require 'test-common.pl';
use File::Spec;

my $text = <<TEXT;
then i heard the voices on a broadcast from up on the bird
they were getting interviewed by some Goodman whose name was Bill
i'm almost there to Vegas where they're puttin' on a show
they've come so far i've lived this long at least i must just go and say hello
TEXT

my $key_id = '39F560A90D7F1559';
my $pass = "foobar";
my $uid = 'Foo Bar <foo@bar.com>';

my $secring = File::Spec->catfile($SAMPLES, 'gpg', 'ring.sec');
my $pubring = File::Spec->catfile($SAMPLES, 'gpg', 'ring.pub');
my $pgp = Crypt::OpenPGP->new(
                   SecRing => $secring,
                   PubRing => $pubring,
              );
ok($pgp);

my($sig, $signer);

## Test standard armoured signature.
$sig = $pgp->sign(
               KeyID    => $key_id,
               Data     => $text,
               Armour   => 1,
               Passphrase => $pass,
            );
ok($sig);
ok($sig =~ /^-----BEGIN PGP MESSAGE/);
$signer = $pgp->verify( Signature => $sig );
ok($signer, $uid);

## Test detached signature.
$sig = $pgp->sign(
               KeyID    => $key_id,
               Data     => $text,
               Detach   => 1,
               Armour   => 1,
               Passphrase => $pass,
            );
ok($sig);
ok($sig =~ /^-----BEGIN PGP SIGNATURE/);
$signer = $pgp->verify( Signature => $sig );
ok(!$signer);
ok($pgp->errstr =~ /Reading data files failed/);
$signer = $pgp->verify( Signature => $sig, Data => $text );
ok($signer, $uid);

## Test unarmoured signature.
$sig = $pgp->sign(
               KeyID    => $key_id,
               Data     => $text,
               Passphrase => $pass,
            );
ok($sig);
ok($sig !~ /^-----BEGIN PGP MESSAGE/);
$signer = $pgp->verify( Signature => $sig );
ok($signer, $uid);

## Test clear-text signature.
$sig = $pgp->sign(
               KeyID      => $key_id,
               Data       => $text,
               Passphrase => $pass,
               Clearsign  => 1,
            );
ok($sig);
ok($sig =~ /^-----BEGIN PGP SIGNED MESSAGE/);
$signer = $pgp->verify( Signature => $sig );
ok($signer, $uid);

## Test using Key param to sign and verify.
my $ring = Crypt::OpenPGP::KeyRing->new( Filename => $pgp->{SecRing} );
my $kb = $ring->find_keyblock_by_keyid(pack 'H*', $key_id);
my $cert = $kb->signing_key;
$cert->unlock($pass);
$sig = $pgp->sign(
               Key        => $cert,
               Data       => $text,
            );
ok($sig);
$signer = $pgp->verify( Signature => $sig, Key => $cert->public_cert );
ok($signer, 1);
