# $Id: 05-packets.t,v 1.1 2001/07/27 07:52:48 btrott Exp $

use Test;
use Crypt::OpenPGP::PacketFactory;
use Crypt::OpenPGP::Plaintext;
use Crypt::OpenPGP::UserID;
use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::Constants qw( PGP_PKT_USER_ID PGP_PKT_PLAINTEXT );

BEGIN { plan tests => 22 }

## 184 bytes
my $text = <<TEXT;
we are the synchronizers
send messages through time code
midi clock rings in my mind
machines gave me some freedom
synthesizers gave me some wings
they drop me through 12 bit samplers
TEXT

my $id = 'Foo Bar <foo@bar.com>';

## Saving packets
my $pt = Crypt::OpenPGP::Plaintext->new( Data => $text );
ok($pt);
my $ptdata = $pt->save;
my $ser = Crypt::OpenPGP::PacketFactory->save($pt);
ok($ser);
ok(length($ser) - length($ptdata), 2);   ## 1 ctb tag, 1 length byte

## Test pkt_hdrlen override of hdrlen calculation
## Force Plaintext packets to use 2-byte length headers
*Crypt::OpenPGP::Plaintext::pkt_hdrlen =
*Crypt::OpenPGP::Plaintext::pkt_hdrlen = sub { 2 };

$ser = Crypt::OpenPGP::PacketFactory->save($pt);
ok($ser);
ok(length($ser) - length($ptdata), 3);   ## 1 ctb tag, 2 length byte

## Reading packets from serialized buffer
my $buf = Crypt::OpenPGP::Buffer->new;
$buf->append($ser);
my $pt2 = Crypt::OpenPGP::PacketFactory->parse($buf);
ok($pt2);
ok(ref($pt2), 'Crypt::OpenPGP::Plaintext');
ok($pt2->{timestamp}, $pt->{timestamp});
ok($pt2->{filename}, $pt->{filename});
ok($pt2->{mode}, $pt->{mode});
ok($pt2->{data}, $pt->{data});

## Saving multiple packets
my $userid = Crypt::OpenPGP::UserID->new( Identity => $id );
ok($userid);
$ser = Crypt::OpenPGP::PacketFactory->save($pt, $userid, $pt);
ok($ser);

$buf = Crypt::OpenPGP::Buffer->new;
$buf->append($ser);

my(@pkts, $pkt);
push @pkts, $pkt while $pkt = Crypt::OpenPGP::PacketFactory->parse($buf);
ok(@pkts == 3);
ok(ref($pkts[0]), 'Crypt::OpenPGP::Plaintext');
ok(ref($pkts[1]), 'Crypt::OpenPGP::UserID');
ok(ref($pkts[2]), 'Crypt::OpenPGP::Plaintext');

## Test finding specific packets

@pkts = ();
$buf->{offset} = 0;
push @pkts, $pkt
    while $pkt = Crypt::OpenPGP::PacketFactory->parse($buf,
        [ PGP_PKT_USER_ID ]);
ok(@pkts == 1);
ok(ref($pkts[0]), 'Crypt::OpenPGP::UserID');

@pkts = ();
$buf->{offset} = 0;
push @pkts, $pkt
    while $pkt = Crypt::OpenPGP::PacketFactory->parse($buf,
        [ PGP_PKT_PLAINTEXT ]);
ok(@pkts == 2);
ok(ref($pkts[0]), 'Crypt::OpenPGP::Plaintext');
ok(ref($pkts[1]), 'Crypt::OpenPGP::Plaintext');
