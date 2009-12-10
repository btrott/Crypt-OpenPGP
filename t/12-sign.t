use strict;
use Test::More tests => 12;

use Crypt::OpenPGP;

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

my $secring = File::Spec->catfile( $SAMPLES, 'gpg', 'ring.sec' );
my $pubring = File::Spec->catfile( $SAMPLES, 'gpg', 'ring.pub' );
my $pgp = Crypt::OpenPGP->new(
    SecRing => $secring,
    PubRing => $pubring,
);
isa_ok $pgp, 'Crypt::OpenPGP';

{
    diag 'armoured sig';

    # Test standard armoured signature.
    my $sig = $pgp->sign(
        KeyID       => $key_id,
        Data        => $text,
        Armour      => 1,
        Passphrase  => $pass,
    );
    like $sig, qr/^-----BEGIN PGP MESSAGE/, 'message is armoured';
    my $signer = $pgp->verify( Signature => $sig );
    is $signer, $uid, 'verified as signed by uid';
}

{
    diag 'detached sig';

    # Test detached signature.
    my $sig = $pgp->sign(
        KeyID       => $key_id,
        Data        => $text,
        Detach      => 1,
        Armour      => 1,
        Passphrase  => $pass,
    );
    like $sig, qr/^-----BEGIN PGP SIGNATURE/, 'sig is armoured';
    my $signer = $pgp->verify( Signature => $sig );
    ok !$signer, 'can\'t verify detached sig without datafile';
    like $pgp->errstr, qr/Reading data files failed/, 'errstr matches';
    $signer = $pgp->verify( Signature => $sig, Data => $text );
    is $signer, $uid, 'verified as signed by uid';
}

{
    diag 'unarmoured sig';

    # Test unarmoured signature.
    my $sig = $pgp->sign(
        KeyID       => $key_id,
        Data        => $text,
        Passphrase  => $pass,
    );
    unlike $sig, qr/^-----BEGIN PGP MESSAGE/, 'message is not armoured';
    my $signer = $pgp->verify( Signature => $sig );
    is $signer, $uid, 'verified as signed by uid';
}

{
    diag 'clear-text sig';

    # Test clear-text signature.
    my $sig = $pgp->sign(
        KeyID      => $key_id,
        Data       => $text,
        Passphrase => $pass,
        Clearsign  => 1,
    );
    like $sig, qr/^-----BEGIN PGP SIGNED MESSAGE/, 'message is armoured';
    my $signer = $pgp->verify( Signature => $sig );
    is $signer, $uid, 'verified as signed by uid';
}

{
    diag 'sig generated using explicit Key';

    # Test using Key param to sign and verify.
    my $ring = Crypt::OpenPGP::KeyRing->new(
        Filename => $pgp->{cfg}->get('SecRing')
    );
    my $kb = $ring->find_keyblock_by_keyid( pack 'H*', $key_id );
    my $cert = $kb->signing_key;
    $cert->unlock( $pass );
    my $sig = $pgp->sign(
        Key     => $cert,
        Data    => $text,
    );
    my $is_valid = $pgp->verify( Signature => $sig, Key => $cert->public_cert );
    ok $is_valid, 'signature signed by Key is valid';
}