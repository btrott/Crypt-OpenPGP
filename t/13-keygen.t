# $Id: 13-keygen.t,v 1.3 2001/07/27 05:28:17 btrott Exp $

use Test;
use Crypt::OpenPGP;
use Crypt::OpenPGP::Message;
use strict;

BEGIN { plan tests => 22 }

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

        my $sig = $pub->get('Crypt::OpenPGP::Signature')->[0];
        my $dgst = $sig->hash_data($pub->key);
        ok($pub->key->key->verify($sig, $dgst));

        my $saved = $pub->save;
        my $msg = Crypt::OpenPGP::Message->new;
        $msg->read( Data => $saved );
        my @pieces = @{ $msg->{pieces} };
        ok(ref($pieces[0]), 'Crypt::OpenPGP::Certificate');
        ok(ref($pieces[1]), 'Crypt::OpenPGP::UserID');
        ok(ref($pieces[2]), 'Crypt::OpenPGP::Signature');

        ok($pieces[0]->key_id, $sec->key->key_id);
    }
#}
