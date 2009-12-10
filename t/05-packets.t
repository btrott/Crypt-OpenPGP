use strict;
use Test::More tests => 19;

use Crypt::OpenPGP::Plaintext;
use Crypt::OpenPGP::UserID;
use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::Constants qw( PGP_PKT_USER_ID PGP_PKT_PLAINTEXT );

use_ok 'Crypt::OpenPGP::PacketFactory';

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

# Saving packets
my $pt = Crypt::OpenPGP::Plaintext->new( Data => $text );
isa_ok $pt, 'Crypt::OpenPGP::Plaintext';
my $ptdata = $pt->save;
my $ser = Crypt::OpenPGP::PacketFactory->save( $pt );
ok $ser, 'save serializes our packet';
# 1 ctb tag, 1 length byte
is length( $ser ) - length( $ptdata ), 2, '2 bytes for header';

# Test pkt_hdrlen override of hdrlen calculation
# Force Plaintext packets to use 2-byte length headers
*Crypt::OpenPGP::Plaintext::pkt_hdrlen =
*Crypt::OpenPGP::Plaintext::pkt_hdrlen = sub { 2 };

$ser = Crypt::OpenPGP::PacketFactory->save( $pt );
ok $ser, 'save serializes our packet';
# 1 ctb tag, 2 length byte
is length( $ser ) - length( $ptdata ), 3, 'now 3 bytes per header';

# Reading packets from serialized buffer
my $buf = Crypt::OpenPGP::Buffer->new;
$buf->append( $ser );
my $pt2 = Crypt::OpenPGP::PacketFactory->parse( $buf );
isa_ok $pt2, 'Crypt::OpenPGP::Plaintext';
is_deeply $pt, $pt2, 'parsing serialized packet yields original';

# Saving multiple packets
my $userid = Crypt::OpenPGP::UserID->new( Identity => $id );
isa_ok $userid, 'Crypt::OpenPGP::UserID';
$ser = Crypt::OpenPGP::PacketFactory->save( $pt, $userid, $pt );
ok $ser, 'save serializes our packet';

$buf = Crypt::OpenPGP::Buffer->new;
$buf->append( $ser );

my( @pkts, $pkt );
push @pkts, $pkt while $pkt = Crypt::OpenPGP::PacketFactory->parse( $buf );
is_deeply \@pkts, [ $pt, $userid, $pt ],
    'parsing multiple packets gives us back all 3 originals';

# Test finding specific packets
@pkts = ();
$buf->reset_offset;
push @pkts, $pkt
    while $pkt = Crypt::OpenPGP::PacketFactory->parse(
        $buf,
        [ PGP_PKT_USER_ID ]
    );
is_deeply \@pkts, [ $userid ], 'only 1 userid packet found';

@pkts = ();
$buf->reset_offset;
push @pkts, $pkt
    while $pkt = Crypt::OpenPGP::PacketFactory->parse(
        $buf,
        [ PGP_PKT_PLAINTEXT ]
    );
is_deeply \@pkts, [ $pt, $pt ], '2 plaintext packets found';

# Test finding, but not parsing, specific packets

@pkts = ();
$buf->reset_offset;
push @pkts, $pkt
    while $pkt = Crypt::OpenPGP::PacketFactory->parse(
        $buf,
        [ PGP_PKT_PLAINTEXT, PGP_PKT_USER_ID ],
        [ PGP_PKT_USER_ID ],
    );
is @pkts, 3, 'found all 3 packets';
isa_ok $pkts[0], 'HASH';
ok $pkts[0]->{__unparsed}, 'plaintext packets are unparsed';
is_deeply $pkts[1], $userid, 'userid packets are parsed';
isa_ok $pkts[2], 'HASH';
ok $pkts[2]->{__unparsed}, 'plaintext packets are unparsed';