# $Id: UserID.pm,v 1.4 2001/07/26 07:10:22 btrott Exp $

package Crypt::OpenPGP::UserID;
use strict;

use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub new {
    my $id = bless { }, shift;
    $id->init(@_);
}

sub init {
    my $id = shift;
    my %param = @_;
    if (my $ident = $param{Identity}) {
        $id->{id} = $ident;
    }
    $id;
}

sub id { $_[0]->{id} }
sub parse {
    my $class = shift;
    my($buf) = @_;
    my $id = $class->new;
    $id->{id} = $buf->bytes;
    $id;
}

sub save { $_[0]->{id} }

1;
