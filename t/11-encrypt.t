# $Id: 11-encrypt.t,v 1.5 2001/08/09 05:40:23 btrott Exp $

use Test;
use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;
use strict;

BEGIN { plan tests => 17 }

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
my $passphrase = "foobar";

my $secring = File::Spec->catfile($SAMPLES, 'gpg', 'ring.sec');
my $pubring = File::Spec->catfile($SAMPLES, 'gpg', 'ring.pub');
my $pgp = Crypt::OpenPGP->new(
                   SecRing => $secring,
                   PubRing => $pubring,
              );
ok($pgp);

my $ct = $pgp->encrypt(
               KeyID    => $key_id,
               Data     => $text,
               Armour   => 1,
            );
ok($ct);
ok($ct =~ /^-----BEGIN PGP MESSAGE/);

my $pt = $pgp->decrypt(
               Data       => $ct,
               Passphrase => $passphrase,
            );
ok($pt);

ok($pt eq $text);

$ct = $pgp->encrypt(
               KeyID    => $key_id,
               Data     => $text,
            );
ok($ct);
ok($ct !~ /^-----BEGIN PGP MESSAGE/);

$pt = $pgp->decrypt(
               Data       => $ct,
               Passphrase => $passphrase,
            );
ok($pt);

ok($pt eq $text);

## Now test conventional encryption; might as well just
## reuse the passphrase.

$ct = $pgp->encrypt(
               Passphrase => $passphrase,
               Data       => $text,
            );
ok($ct);

$pt = $pgp->decrypt(
               Data       => $ct,
               Passphrase => $passphrase,
            );
ok($pt);
ok($pt eq $text);

## Now test encrypted-MDC packets.

$ct = $pgp->encrypt(
               Passphrase => $passphrase,
               Data       => $text,
               MDC        => 1,
            );
ok($ct);
my $msg = Crypt::OpenPGP::Message->new;
$msg->read( Data => $ct );
ok(ref($msg->{pieces}->[-1]), 'Crypt::OpenPGP::Ciphertext');
ok($msg->{pieces}->[-1]->{is_mdc});

$pt = $pgp->decrypt(
               Data       => $ct,
               Passphrase => $passphrase,
            );
ok($pt);
ok($pt eq $text);
