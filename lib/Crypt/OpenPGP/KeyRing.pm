# $Id: KeyRing.pm,v 1.8 2001/07/26 17:33:14 btrott Exp $

package Crypt::OpenPGP::KeyRing;
use strict;

use Crypt::OpenPGP::Constants qw( PGP_PKT_PUBLIC_KEY
                                  PGP_PKT_SECRET_KEY
                                  PGP_PKT_PUBLIC_SUBKEY
                                  PGP_PKT_SECRET_SUBKEY );
use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::KeyBlock;
use Crypt::OpenPGP::PacketFactory;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub new {
    my $class = shift;
    my $ring = bless { }, $class;
    $ring->init(@_);
}

sub init {
    my $ring = shift;
    my %param = @_;
    $ring->{_data} = $param{Data} || '';
    if (!$ring->{_data} && (my $file = $param{Filename})) {
        local *FH;
        open FH, $file or return $ring->error("Can't open keyring $file: $!");
        { local $/; $ring->{_data} = <FH> }
        close FH;
    }
    if ($ring->{_data} =~ /-----BEGIN/) {
        require Crypt::OpenPGP::Armour;
        my $rec = Crypt::OpenPGP::Armour->unarmour($ring->{_data}) or
            return (ref $ring)->error("Unarmour failed: " .
                Crypt::OpenPGP::Armour->errstr);
        $ring->{_data} = $rec->{Data};
    }
    $ring;
}

sub read {
    my $ring = shift;
    return $ring->error("No data to read") unless $ring->{_data};
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->append($ring->{_data});
    $ring->restore($buf);
    1;
}

sub restore {
    my $ring = shift;
    my($buf) = @_;
    $ring->{blocks} = [];
    my($kb);
    while (my $packet = Crypt::OpenPGP::PacketFactory->parse($buf)) {
        if (ref($packet) eq "Crypt::OpenPGP::Certificate" &&
            !$packet->is_subkey) {
            $kb = Crypt::OpenPGP::KeyBlock->new;
            $ring->add($kb);
        }
        $kb->add($packet) if $kb;
    }
}

sub add {
    my $ring = shift;
    my($entry) = @_;
    push @{ $ring->{blocks} }, $entry;
}

sub get_by_keyid {
    my $ring = shift;
    my($key_id) = @_;
    my @blocks = $ring->blocks;
    for my $kb (@blocks) {
        my $cert = $kb->key;
        return $cert if $cert->key_id eq $key_id;
    }
}

sub find_keyblock_by_keyid {
    my $ring = shift;
    my($key_id) = @_;
    return $ring->error("No data to read") unless $ring->{_data};
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->append($ring->{_data});
    my(%offsets, $last_kb_start_cert, $last_kid);
    while (my $cert = Crypt::OpenPGP::PacketFactory->parse($buf,
                      [ PGP_PKT_SECRET_KEY, PGP_PKT_PUBLIC_KEY,
                        PGP_PKT_SECRET_SUBKEY, PGP_PKT_PUBLIC_SUBKEY ])) {
        my $this_kid = $cert->key_id;
        $last_kb_start_cert = $cert,
        $last_kid = $this_kid,
        $offsets{$this_kid} = $buf->offset
            unless $cert->is_subkey;
        next unless $this_kid eq $key_id;
        my $kb = Crypt::OpenPGP::KeyBlock->new;

        if ($cert->is_subkey) {
            ## Rewind buffer to offset after last keyblock start-cert
            $buf->{offset} = $offsets{$last_kid};
            $kb->add($last_kb_start_cert);
        }
            
        $kb->add($cert);
        {
            my $packet = Crypt::OpenPGP::PacketFactory->parse($buf);
            last unless $packet;
            last if ref($packet) eq "Crypt::OpenPGP::Certificate" &&
                    !$packet->is_subkey;
            $kb->add($packet) if $kb;
            redo;
        }
        return wantarray ? ($kb, $cert) : $kb;
    }
}

sub blocks { $_[0]->{blocks} ? @{ $_[0]->{blocks} } : () }

1;
