# $Id: 13-keygen.t,v 1.6 2002/02/09 18:32:58 btrott Exp $

use Test;
use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;
use strict;

BEGIN { plan tests => 28 }

my $id = 'Black Francis <frank@black.com>';
my $pass = 'foobar';

my $pgp = Crypt::OpenPGP->new;

my $bits = 512;

## 1024 bits was taking too long, and since this is just a test,
## it wasn't necessary; we're testing the same functionality
## no matter the key size.

#for my $bits (qw( 512 1024 )) {
    for my $type (qw( RSA DSA )) {
        my($pub, $sec) = $pgp->keygen(
                            Type       => $type,
                            Size       => $bits,
                            Passphrase => $pass,
                            Identity   => $id,
                 );
        ok($pub);
        ok($sec);
        ok($pub->key);
        ok($sec->key);
        ok($pub->key->key_id, $sec->key->key_id);
        ok($pub->primary_uid, $id);
        ok($pub->key->key->size, $bits);
        ok($sec->key->key->size, $bits);

        my $uid = $pub->get('Crypt::OpenPGP::UserID')->[0];
        my $sig = $pub->get('Crypt::OpenPGP::Signature')->[0];
        my $dgst = $sig->hash_data($pub->key, $uid);
        ok($pub->key->key->verify($sig, $dgst));

        my $saved = $pub->save;
        my $msg = Crypt::OpenPGP::Message->new( Data => $saved );
        ok($msg);
        my @pieces = $msg->pieces;
        ok(ref($pieces[0]), 'Crypt::OpenPGP::Certificate');
        ok(ref($pieces[1]), 'Crypt::OpenPGP::UserID');
        ok(ref($pieces[2]), 'Crypt::OpenPGP::Signature');

        ok($pieces[0]->key_id, $sec->key->key_id);
    }
#}
