# $Id: PacketFactory.pm,v 1.12 2001/07/27 07:24:38 btrott Exp $

package Crypt::OpenPGP::PacketFactory;
use strict;

use Crypt::OpenPGP::Constants qw( :packet );
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

use vars qw( %PACKET_TYPES %PACKET_TYPES_BY_CLASS );
%PACKET_TYPES = (
    PGP_PKT_PUBKEY_ENC()    => { class => 'Crypt::OpenPGP::SessionKey' },
    PGP_PKT_SIGNATURE()     => { class => 'Crypt::OpenPGP::Signature' },
    PGP_PKT_ONEPASS_SIG()   => { class => 'Crypt::OpenPGP::OnePassSig' },
    PGP_PKT_SECRET_KEY()    => { class => 'Crypt::OpenPGP::Certificate',
                                 args  => [ 1, 0 ] },
    PGP_PKT_PUBLIC_KEY()    => { class => 'Crypt::OpenPGP::Certificate',
                                 args  => [ 0, 0 ] },
    PGP_PKT_SECRET_SUBKEY() => { class => 'Crypt::OpenPGP::Certificate',
                                 args  => [ 1, 1 ] },
    PGP_PKT_USER_ID()       => { class => 'Crypt::OpenPGP::UserID' },
    PGP_PKT_PUBLIC_SUBKEY() => { class => 'Crypt::OpenPGP::Certificate',
                                 args  => [ 0, 1 ] },
    PGP_PKT_COMPRESSED()    => { class => 'Crypt::OpenPGP::Compressed' },
    PGP_PKT_ENCRYPTED()     => { class => 'Crypt::OpenPGP::Ciphertext' },
    PGP_PKT_MARKER()        => { class => 'Crypt::OpenPGP::Marker' },
    PGP_PKT_PLAINTEXT()     => { class => 'Crypt::OpenPGP::Plaintext' },
    PGP_PKT_RING_TRUST()    => { class => 'Crypt::OpenPGP::Trust' },
);

%PACKET_TYPES_BY_CLASS = map { $PACKET_TYPES{$_}{class} => $_ } keys %PACKET_TYPES;

sub parse {
    my $class = shift;
    my($buf, $find) = @_;
    return unless $buf && $buf->offset < $buf->length;
    my %find;
    if ($find) {
        %find = ref($find) eq 'ARRAY' ? (map { $_ => 1 } @$find) :
                                        ($find => 1);
    }

    my($type, $len, $b);
    if (keys %find) {
        do {
            ($type, $len) = $class->_parse_header($buf);
            $b = $buf->extract($len ? $len : $buf->length - $buf->offset);
            return unless $type;
        } while !$find{$type};                          ## Skip
    }
    else {
        ($type, $len) = $class->_parse_header($buf);
        $b = $buf->extract($len ? $len : $buf->length - $buf->offset);
    }


    my $obj;
    if (my $ref = $PACKET_TYPES{$type}) {
        my $pkt_class = $ref->{class};
        my @args = $ref->{args} ? @{ $ref->{args} } : ();
        eval "use $pkt_class;";
        return $class->error("Loading $pkt_class failed: $@") if $@;
        $obj = $pkt_class->parse($b, @args);
    }
    else {
        $obj = { type => $type, length => $len };
    }
    $obj;
}

sub _parse_header {
    my $class = shift;
    my($buf) = @_;
    return unless $buf && $buf->offset < $buf->length;

    my $tag = $buf->get_int8;
    return $class->error("Parse error: bit 7 not set!")
        unless $tag & 0x80;
    my $is_new = $tag & 0x40;
    my($type, $len);
    if ($is_new) {
        $type = $tag & 0x3f;
        my $lb1 = $buf->get_int8;
        if ($lb1 <= 191) {
            $len = $lb1;
        } elsif ($lb1 <= 223) {
            $len = (($lb1-192) << 8) + $buf->get_int8 + 192;
        } elsif ($lb1 < 255) {
            $len = 1 << ($lb1 + 0x1f);
        } else {
            $len = $buf->get_int32;
        }
    }
    else {
        $type = ($tag>>2)&0xf;
        my $lenbytes = (($tag&3)==3) ? 0 : (1<<($tag & 3));
        $len = 0;
        for (1..$lenbytes) {
            $len <<= 8;
            $len += $buf->get_int8;
        }
    }
    ($type, $len);
}

sub save {
    my $class = shift;
    my @objs = @_;
    my $ser = '';
    for my $obj (@objs) {
        my $body = $obj->save;
        my $len = length($body);
        my $type = $obj->can('pkt_type') ? $obj->pkt_type :
                   $PACKET_TYPES_BY_CLASS{ref($obj)};
        my $hdrlen = $obj->can('pkt_hdrlen') ? $obj->pkt_hdrlen : undef;
        my $buf = Crypt::OpenPGP::Buffer->new;
        if ($obj->{is_new}) {
        }
        else {
            unless ($hdrlen) {
                if (!defined $len) {
                    $hdrlen = 0;
                } elsif ($len < 256) {
                    $hdrlen = 1;
                } elsif ($len < 65536) {
                    $hdrlen = 2;
                } else {
                    $hdrlen = 4;
                }
            }
            return $class->error("Packet overflow: overflow preset len")
                if $hdrlen == 1 && $len > 255;
            $hdrlen = 4 if $hdrlen == 2 && $len > 65535;
            my $tag = 0x80 | ($type << 2);
            if ($hdrlen == 0) {
                $buf->put_int8($tag | 3);
            } elsif ($hdrlen == 1) {
                $buf->put_int8($tag);
                $buf->put_int8($len);
            } elsif ($hdrlen == 2) {
                $buf->put_int8($tag | 1);
                $buf->put_int16($len);
            } else {
                $buf->put_int8($tag | 2);
                $buf->put_int32($len);
            }
            $buf->put_bytes($body);
        }
        $ser .= $buf->bytes;
    }
    $ser;
}

1;
