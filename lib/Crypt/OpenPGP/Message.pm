# $Id: Message.pm,v 1.3 2001/07/21 06:54:27 btrott Exp $

package Crypt::OpenPGP::Message;
use strict;

use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::PacketFactory;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub new { bless { }, $_[0] }

sub read {
    my $msg = shift;
    my %param = @_;
    my($data);
    unless ($data = $param{Data}) {
        my $file = $param{Filename} or
            return $msg->error("Must supply either Data or Filename");
        local *FH;
        open FH, $file or
            return $msg->error("Failed opening file $file: $!");
        { local $/; $data = <FH> }
        close FH;
    }
    if ($data =~ /-----BEGIN/) {
        require Crypt::OpenPGP::Armour;
        my $rec = Crypt::OpenPGP::Armour->unarmour($data) or
            return $msg->error("Unarmour failed: " .
                Crypt::OpenPGP::Armour->errstr);
        $data = $rec->{Data};
    }
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->append($data);
    $msg->restore($buf);
    1;
}

sub restore {
    my $msg = shift;
    my($buf) = @_;
    $msg->{pieces} = [];
    while (my $packet = Crypt::OpenPGP::PacketFactory->parse($buf)) {
        push @{ $msg->{pieces} }, $packet;
    }
}

1;
