# $Id: 09-config.t,v 1.1 2001/08/30 04:19:27 btrott Exp $

use Test;
use Crypt::OpenPGP;
use Crypt::OpenPGP::Config;
use strict;

BEGIN { plan tests => 20 };

use vars qw( $SAMPLES );
unshift @INC, 't/';
require 'test-common.pl';
use File::Spec;

my($cfg_file, $cfg, $pgp);

### TEST GNUPG CONFIG
$cfg_file = File::Spec->catfile($SAMPLES, 'cfg.gnupg');

$cfg = Crypt::OpenPGP::Config->new;
ok($cfg);
ok( $cfg->read_config('GnuPG', $cfg_file) );

## Test standard str directive
ok($cfg->get('Digest'), 'MD5');
$cfg->set('Digest', 'SHA1');
ok($cfg->get('Digest'), 'SHA1');

## Test standard bool directive, no arg (eg. 'armor')
ok($cfg->get('Armour'), 1);
$cfg->set('Armour', 0);
ok($cfg->get('Armour'), 0);

## Test special Cipher directive (eg. 'cipher-alg TWOFISH')
ok($cfg->get('Cipher'), 'Twofish');

## Test special Compress directive
ok($cfg->get('Compress'), 'Zlib');

## Test that config file gets read correctly when passed to
## constructor.
$pgp = Crypt::OpenPGP->new( ConfigFile => $cfg_file, Compat => 'GnuPG' );
ok($pgp);
ok($pgp->{cfg});
ok($pgp->{cfg}->get('Armour'), 1);

### TEST PGP2 CONFIG
$cfg_file = File::Spec->catfile($SAMPLES, 'cfg.pgp2');

$cfg = Crypt::OpenPGP::Config->new;
ok($cfg);
ok( $cfg->read_config('PGP2', $cfg_file) );

## Test standard str directive
ok($cfg->get('PubRing'), 'foo.pubring');
$cfg->set('PubRing', 'bar.pubring');
ok($cfg->get('PubRing'), 'bar.pubring');

## Test standard bool directive, with arg (eg. 'Armor on')
ok($cfg->get('Armour'), 1);
$cfg->set('Armour', 0);
ok($cfg->get('Armour'), 0);

## Test that config file gets read correctly when passed to
## constructor.
$pgp = Crypt::OpenPGP->new( ConfigFile => $cfg_file, Compat => 'PGP2' );
ok($pgp);
ok($pgp->{cfg});
ok($pgp->{cfg}->get('Armour'), 1);
