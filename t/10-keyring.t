# $Id: 10-keyring.t,v 1.4 2001/07/25 20:53:22 btrott Exp $

use Test;
use Crypt::OpenPGP::KeyRing;
use strict;

BEGIN { plan tests => 9 }

use vars qw( $SAMPLES );
unshift @INC, 't/';
require 'test-common.pl';
use File::Spec;

my $key_id = '39F560A90D7F1559';
my $passphrase = "foobar";

my $ring = Crypt::OpenPGP::KeyRing->new( Filename =>
    File::Spec->catfile($SAMPLES, 'gpg', 'ring.sec') );
ok($ring);
ok($ring->read);
my @blocks = $ring->blocks;
ok(@blocks == 1);
ok(my $kb = $blocks[0]);
ok(my $cert = $kb->key);
ok($cert->is_protected);
ok($cert->key_id, pack('H*', $key_id));
ok($cert->unlock($passphrase));
ok($kb->primary_uid, "Foo Bar <foo\@bar.com>");
