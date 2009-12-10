use strict;
use Test::More tests => 21;
use Test::Exception;

use_ok 'Crypt::OpenPGP::KeyRing';

use vars qw( $SAMPLES );
unshift @INC, 't/';
require 'test-common.pl';
use File::Spec;

my $key_id = '39F560A90D7F1559';
my $packed_key_id = pack 'H*', $key_id;
my $passphrase = "foobar";
my $uid = q(Foo Bar <foo@bar.com>);

my $ring = Crypt::OpenPGP::KeyRing->new(
    Filename => File::Spec->catfile($SAMPLES, 'gpg', 'ring.sec')
);
isa_ok $ring, 'Crypt::OpenPGP::KeyRing';

my( $kb, $cert );

# Read the entire ring and look at each block
lives_ok { $ring->read } 'ring->read succeeds';
my @blocks = $ring->blocks;
is @blocks, 1, '1 block';
$kb = $blocks[0];
isa_ok $kb, 'Crypt::OpenPGP::KeyBlock';
$cert = $kb->key;
isa_ok $cert, 'Crypt::OpenPGP::Certificate';
ok $cert->is_protected, 'cert is protected';
is $cert->key_id, $packed_key_id, 'key_id matches';
lives_ok { $cert->unlock( $passphrase ) } 'cert->unlock succeeds';
is $kb->primary_uid, $uid, 'primary_uid matches';

# Do lookups by key ID
# First, try the failure case.
$kb = $ring->find_keyblock_by_keyid( 'foo' );
ok !$kb, 'can\'t find key that doesn\'t exist';

# Lookup entire key ID
$kb = $ring->find_keyblock_by_keyid( $packed_key_id );
isa_ok $kb, 'Crypt::OpenPGP::KeyBlock';
is $kb->key->key_id, $packed_key_id, 'found the right key by key id';

# Lookup last 4 bytes of key ID (8 hex digits)
$kb = $ring->find_keyblock_by_keyid( substr $packed_key_id, -4, 4 );
isa_ok $kb, 'Crypt::OpenPGP::KeyBlock';
is $kb->key->key_id, $packed_key_id, 'found the right key by last-4 bytes';

# Do lookups by user ID
$kb = $ring->find_keyblock_by_uid( $uid );
isa_ok $kb, 'Crypt::OpenPGP::KeyBlock';
is $kb->key->key_id, $packed_key_id, 'found the right key by uid';
is $kb->primary_uid, $uid, 'primary_uid matches';

# lookup by uid should be case insensitive.
$kb = $ring->find_keyblock_by_uid( uc $uid );
isa_ok $kb, 'Crypt::OpenPGP::KeyBlock';
is $kb->key->key_id, $packed_key_id,
    'found the right key by upper-cased uid';
is $kb->primary_uid, $uid, 'primary_uid matches';