use strict;
use Test::More tests => 29;

use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;

my $id = 'Black Francis <frank@black.com>';
my $pass = 'foobar';

my $pgp = Crypt::OpenPGP->new;

my $bits = 512;

for my $type ( qw( RSA DSA ) ) {
    diag $type;

    my( $pub, $sec ) = $pgp->keygen(
        Type        => $type,
        Size        => $bits,
        Passphrase  => $pass,
        Identity    => $id,
    );
    isa_ok $pub, 'Crypt::OpenPGP::KeyBlock';
    isa_ok $sec, 'Crypt::OpenPGP::KeyBlock';
    
    isa_ok $pub->key, 'Crypt::OpenPGP::Certificate';
    isa_ok $sec->key, 'Crypt::OpenPGP::Certificate';

    is $pub->key->key_id, $sec->key->key_id,
        'public key_id matches secret key_id';

    is $pub->primary_uid, $id, 'primary_uid matches';

    is $pub->key->key->size, $bits, 'keysize (in bits) matches for pubkey';
    is $sec->key->key->size, $bits, 'keysize (in bits) matches for seckey';

    my $uid = $pub->get( 'Crypt::OpenPGP::UserID' )->[0];
    my $sig = $pub->get( 'Crypt::OpenPGP::Signature' )->[0];
    my $dgst = $sig->hash_data( $pub->key, $uid );
    ok $pub->key->key->verify( $sig, $dgst ), 'self-signature verifies';

    my $saved = $pub->save;
    my $msg = Crypt::OpenPGP::Message->new( Data => $saved );
    isa_ok $msg, 'Crypt::OpenPGP::Message';
    my @pieces = $msg->pieces;
    isa_ok $pieces[0], 'Crypt::OpenPGP::Certificate';
    isa_ok $pieces[1], 'Crypt::OpenPGP::UserID';
    isa_ok $pieces[2], 'Crypt::OpenPGP::Signature';

    is $pieces[0]->key_id, $sec->key->key_id,
        'serialized public key_id matches secret key_id';
}

{
    *Crypt::RSA::Key::generate = sub {
        my ($self, %params) = @_;
        return $self->error("d is too small. Regenerate.");
    };

    my($pub, $sec) = Crypt::OpenPGP::Key->keygen(
        'RSA',
        Size    => $bits,
        Version => 4,
    );

    is(
        Crypt::OpenPGP::Key->errstr,
        "Key generation failed: d is too small. Regenerate.\n",
        'RSA key generation error got propagated',
    );
}
