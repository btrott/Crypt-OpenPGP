# $Id: 11-encrypt.t,v 1.10 2001/08/11 07:38:50 btrott Exp $

use Test;
use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;
use strict;

BEGIN { plan tests => 39 }

use vars qw( $SAMPLES );
unshift @INC, 't/';
require 'test-common.pl';
use File::Spec;

my $text = <<TEXT;
J'ai tombe sur cette chienne
Shampooineuse
Comme deux rahat-loukoums
A la rose qui rebondissent sur ma nuque boum boum
TEXT

my $key_id = '2988D2905AF8F320';
my $key_id2 = '576B010D0F7199D3';
my $pass = "foobar";
my $uid = 'foo@bar';

my $secring = File::Spec->catfile($SAMPLES, 'gpg', 'ring.sec');
my $pubring = File::Spec->catfile($SAMPLES, 'gpg', 'ring.pub');
my $pgp = Crypt::OpenPGP->new(
                   SecRing => $secring,
                   PubRing => $pubring,
              );
ok($pgp);

my($ct, $pt);

## Test unarmoured encrypted data.
$ct = $pgp->encrypt(
               KeyID    => $key_id,
               Data     => $text,
            );
ok($ct);
ok($ct !~ /^-----BEGIN PGP MESSAGE/);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Test armoured encrypted data.
$ct = $pgp->encrypt(
               KeyID    => $key_id,
               Data     => $text,
               Armour   => 1,
            );
ok($ct);
ok($ct =~ /^-----BEGIN PGP MESSAGE/);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Test compressed encrypted data.
$ct = $pgp->encrypt(
               KeyID    => $key_id,
               Data     => $text,
               Compress => 1,
            );
ok($ct);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Now test conventional encryption; might as well just
## reuse the passphrase.
$ct = $pgp->encrypt(
               Passphrase => $pass,
               Data       => $text,
            );
ok($ct);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Now test encrypted-MDC packets.
$ct = $pgp->encrypt(
               Passphrase => $pass,
               Data       => $text,
               MDC        => 1,
            );
ok($ct);
my $msg = Crypt::OpenPGP::Message->new( Data => $ct );
ok($msg);
my @pieces = $msg->pieces;
ok(ref($pieces[-1]), 'Crypt::OpenPGP::Ciphertext');
ok($pieces[-1]->{is_mdc});
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Test that Recipients param works w/ a key ID.
$ct = $pgp->encrypt(
               Recipients => $key_id,
               Data       => $text,
            );
ok($ct);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Test short key ID.
$ct = $pgp->encrypt(
               Recipients => substr($key_id, -8, 8),
               Data       => $text,
            );
ok($ct);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Test user ID.
$ct = $pgp->encrypt(
               Recipients => $uid,
               Data       => $text,
            );
ok($ct);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Test multiple recipipents, for encrypt and decrypt.
$ct = $pgp->encrypt(
               Recipients => [ $key_id, $key_id ],
               Data       => $text,
            );
ok($ct);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Test multiple recipipents where we don't have secret key
## for the first session key.
$ct = $pgp->encrypt(
               Recipients => [ $key_id2, $key_id ],
               Data       => $text,
            );
ok($ct);
$pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
ok($pt);
ok($pt eq $text);

## Test giving encrypt and decrypt the Key parameter to
## bypass looking up key in keyring.
my $ring = Crypt::OpenPGP::KeyRing->new( Filename => $pgp->{SecRing} );
my $kb = $ring->find_keyblock_by_keyid(pack 'H*', $key_id);
my $cert = $kb->encrypting_key;
$cert->unlock($pass);
$ct = $pgp->encrypt(
               Key        => $cert->public_cert,
               Data       => $text,
            );
ok($ct);
$pt = $pgp->decrypt( Data => $ct, Key => $cert );
ok($pt);
ok($pt eq $text);
