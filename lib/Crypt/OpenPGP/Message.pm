# $Id: Message.pm,v 1.5 2001/07/30 05:36:54 btrott Exp $

package Crypt::OpenPGP::Message;
use strict;

use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::PacketFactory;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub new { bless { pieces => [ ] }, $_[0] }

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
    my $pt;
    if ($data =~ /-----BEGIN PGP SIGNED MESSAGE/) {
        require Crypt::OpenPGP::Armour;
        require Crypt::OpenPGP::Util;
        require Crypt::OpenPGP::Plaintext;
        my($head, $text, $sig) = $data =~
            m!-----BEGIN [^\n\-]+-----(.*?\n\n)?(.+)(-----BEGIN.*?END.*?-----)!s;
        $pt = Crypt::OpenPGP::Plaintext->new(
                              Data => Crypt::OpenPGP::Util::dash_unescape($text),
                              Mode => 't',
                    );
        $data = $sig;
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
    push @{ $msg->{pieces} }, $pt;
    1;
}

sub restore {
    my $msg = shift;
    my($buf) = @_;
    while (my $packet = Crypt::OpenPGP::PacketFactory->parse($buf)) {
        push @{ $msg->{pieces} }, $packet;
    }
}

1;
