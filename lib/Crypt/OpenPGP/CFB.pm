# $Id: CFB.pm,v 1.3 2001/07/24 03:55:16 btrott Exp $

# This code based slightly on the Systemics Crypt::CFB.
# Parts Copyright (C) 1995, 1996 Systemics Ltd (http://www.systemics.com/)
# All rights reserved.

package Crypt::OpenPGP::CFB;
use strict;

sub new {
    my $class = shift;
    my $c = bless { }, $class;
    $c->init(@_);
}

sub init {
    my $c = shift;
    my($cipher, $iv) = @_;
    $c->{cipher} = $cipher;
    $c->{blocksize} = $cipher->blocksize;
    $c->{iv} = $iv || "\0" x $c->{blocksize};
    $c;
}

sub encrypt {
    my $c = shift;
    my($data) = @_;
    my $ret = '';
    my $iv = $c->{iv};
    while ($data) {
        my $out = $c->{cipher}->encrypt($iv);
        my $size = $c->{blocksize};
        my $in = substr $data, 0, $size, '';
        $size -= (my $got = length $in);
        $iv .= ($in ^= substr $out, 0, $got, '');
        substr $iv, 0, $got, '';
        $ret .= $in;
    }
    $c->{iv} = $iv;
    $ret;
}

sub decrypt {
    my $c = shift;
    my($data) = @_;
    my $ret = '';
    my $iv = $c->{iv};
    while ($data) {
        my $out = $c->{cipher}->encrypt($iv);
        my $size = $c->{blocksize};
        my $in = substr $data, 0, $size, '';
        $size -= (my $got = length $in);
        substr $iv .= $in, 0, $got, '';
        $ret .= ($in ^= substr $out, 0, $got, '');
    }
    $c->{iv} = $iv;
    $ret;
}

1;
