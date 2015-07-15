use strict;
use Test::More tests => 38;

use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;

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
my $key_id_sign = '39F560A90D7F1559';
my $pass = "foobar";
my $uid = 'foo@bar';

my $secring = File::Spec->catfile( $SAMPLES, 'gpg', 'ring.sec' );
my $pubring = File::Spec->catfile( $SAMPLES, 'gpg', 'ring.pub' );
my $pgp = Crypt::OpenPGP->new(
    SecRing => $secring,
    PubRing => $pubring,
);
isa_ok $pgp, 'Crypt::OpenPGP';

{
    # Test unarmoured encrypted data.
    my $ct = $pgp->encrypt(
        KeyID    => $key_id,
        Data     => $text,
    );
    ok $ct, 'ciphertext is defined';
    unlike $ct, qr/^-----BEGIN PGP MESSAGE/, 'no armouring';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test armoured encrypted data.
    my $ct = $pgp->encrypt(
        KeyID    => $key_id,
        Data     => $text,
        Armour   => 1,
    );
    ok $ct, 'ciphertext is defined';
    like $ct, qr/^-----BEGIN PGP MESSAGE/, 'armoured';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test compressed encrypted data.
    my $ct = $pgp->encrypt(
        KeyID    => $key_id,
        Data     => $text,
        Compress => 1,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Now test conventional encryption; might as well just
    # reuse the passphrase.
    my $ct = $pgp->encrypt(
        Passphrase => $pass,
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test trailing zeroes.
    my $text = '123456780';
    my $ct = $pgp->encrypt(
        Passphrase => $pass,
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Now test encrypted-MDC packets.
    my $ct = $pgp->encrypt(
        Passphrase => $pass,
        Data       => $text,
        MDC        => 1,
    );
    ok $ct, 'ciphertext is defined';
    my $msg = Crypt::OpenPGP::Message->new( Data => $ct );
    isa_ok $msg, 'Crypt::OpenPGP::Message';
    my @pieces = $msg->pieces;
    isa_ok $pieces[-1], 'Crypt::OpenPGP::Ciphertext';
    ok $pieces[-1]{is_mdc}, 'ciphertext packet is mdc-encrypted';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test that Recipients param works w/ a key ID.
    my $ct = $pgp->encrypt(
        Recipients => $key_id,
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test short key ID.
    my $ct = $pgp->encrypt(
        Recipients => substr( $key_id, -8, 8 ),
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test user ID.
    my $ct = $pgp->encrypt(
        Recipients => $uid,
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test multiple recipipents, for encrypt and decrypt.
    my $ct = $pgp->encrypt(
        Recipients => [ $key_id, $key_id ],
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test multiple recipipents where we don't have secret key
    # for the first session key.
    my $ct = $pgp->encrypt(
        Recipients => [ $key_id2, $key_id ],
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test giving encrypt and decrypt the Key parameter to
    # bypass looking up key in keyring.
    my $ring = Crypt::OpenPGP::KeyRing->new(
        Filename => $pgp->{cfg}->get( 'SecRing' )
    );
    my $kb = $ring->find_keyblock_by_keyid( pack 'H*', $key_id );
    my $cert = $kb->encrypting_key;
    $cert->unlock( $pass );
    my $ct = $pgp->encrypt(
        Key        => $cert->public_cert,
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Key => $cert );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test multiple recipipents where we only pass in the Key
    # for the second key.
    my $ring = Crypt::OpenPGP::KeyRing->new(
        Filename => $pgp->{cfg}->get( 'SecRing' )
    );
    my $kb = $ring->find_keyblock_by_keyid( pack 'H*', $key_id );
    my $cert = $kb->encrypting_key;
    $cert->unlock( $pass );
    my $ct = $pgp->encrypt(
        Recipients => [ $key_id2, $key_id ],
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Key => $cert );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Same, but we pass in the Key for the first key.
    my $ring = Crypt::OpenPGP::KeyRing->new(
        Filename => $pgp->{cfg}->get( 'SecRing' )
    );
    my $kb = $ring->find_keyblock_by_keyid( pack 'H*', $key_id );
    my $cert = $kb->encrypting_key;
    $cert->unlock( $pass );
    my $ct = $pgp->encrypt(
        Recipients => [ $key_id, $key_id2 ],
        Data       => $text,
    );
    ok $ct, 'ciphertext is defined';
    my $pt = $pgp->decrypt( Data => $ct, Key => $cert );
    is $pt, $text, 'decrypting yields original text';
}

{
    # Test encrypting and signing at the same time, with a test of
    # the 3-element return list from decrypt.
    my $ct = $pgp->encrypt(
        KeyID           => $key_id,
        Data            => $text,
        SignKeyID       => $key_id_sign,
        SignPassphrase  => $pass,
    );
    ok $ct, 'ciphertext is defined';
    my( $pt, $valid, $sig ) = $pgp->decrypt( Data => $ct, Passphrase => $pass );
    is $pt, $text, 'decrypting yields original text';
    like $valid, qr/$uid/, 'signature is valid for uid';
    is $sig->key_id, pack( 'H*', $key_id_sign ), 'key_id is correct';
}
