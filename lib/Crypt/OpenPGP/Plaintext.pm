# $Id: Plaintext.pm,v 1.5 2001/07/27 05:26:08 btrott Exp $

package Crypt::OpenPGP::Plaintext;
use strict;

use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub new {
    my $class = shift;
    my $pt = bless { }, $class;
    $pt->init(@_);
}

sub data { $_[0]->{data} }

sub init {
    my $pt = shift;
    my %param = @_;
    if (my $data = $param{Data}) {
        $pt->{data} = $data;
        $pt->{mode} = 'b';
        $pt->{timestamp} = time;
        $pt->{filename} = $param{Filename} || '';
    }
    $pt;
}

sub parse {
    my $class = shift;
    my($buf) = @_;
    my $pt = $class->new;
    $pt->{mode} = $buf->get_char;
    $pt->{filename} = $buf->get_bytes($buf->get_int8);
    $pt->{timestamp} = $buf->get_int32;
    $pt->{data} = $buf->get_bytes( $buf->length - $buf->offset );
    $pt;
}

sub save {
    my $pt = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->put_char($pt->{mode});
    $buf->put_int8(length $pt->{filename});
    $buf->put_bytes($pt->{filename});
    $buf->put_int32($pt->{timestamp});
    $buf->put_bytes($pt->{data});
    $buf->bytes;
}

1;
