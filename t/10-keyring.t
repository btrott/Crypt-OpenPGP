# $Id: 10-keyring.t,v 1.5 2001/08/06 03:39:34 btrott Exp $

use Test;
use Crypt::OpenPGP::KeyRing;
use strict;

BEGIN { plan tests => 19 }

use vars qw( $SAMPLES );
unshift @INC, 't/';
require 'test-common.pl';
use File::Spec;

my $key_id = '39F560A90D7F1559';
my $packed_key_id = pack 'H*', $key_id;
my $passphrase = "foobar";
my $uid = q(Foo Bar <foo@bar.com>);

my $ring = Crypt::OpenPGP::KeyRing->new( Filename =>
    File::Spec->catfile($SAMPLES, 'gpg', 'ring.sec') );
ok($ring);

my($kb, $cert);

## Read the entire ring and look at each block
ok($ring->read);
my @blocks = $ring->blocks;
ok(@blocks == 1);
ok($kb = $blocks[0]);
ok($cert = $kb->key);
ok($cert->is_protected);
ok($cert->key_id, $packed_key_id);
ok($cert->unlock($passphrase));
ok($kb->primary_uid, $uid);

## Do lookups by key ID
## Lookup entire key ID
ok($kb = $ring->find_keyblock_by_keyid($packed_key_id));
ok($cert = $kb->key);
ok($cert->key_id, $packed_key_id);

## Lookup last 4 bytes of key ID (8 hex digits)
ok($kb = $ring->find_keyblock_by_keyid(substr $packed_key_id, -4, 4));
ok($cert = $kb->key);
ok($cert->key_id, $packed_key_id);

## Do lookups by user ID
ok($kb = $ring->find_keyblock_by_uid($uid));
ok($cert = $kb->key);
ok($cert->key_id, $packed_key_id);
ok($kb->primary_uid, $uid);
