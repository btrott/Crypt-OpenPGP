# $Id: Signature.pm,v 1.11 2001/07/27 20:57:28 btrott Exp $

package Crypt::OpenPGP::Signature;
use strict;

use Crypt::OpenPGP::Digest;
use Crypt::OpenPGP::Signature::SubPacket;
use Crypt::OpenPGP::Key::Secret;
use Crypt::OpenPGP::Constants qw( DEFAULT_DIGEST );
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

sub pkt_hdrlen { 2 }

sub key_id {
    my $sig = shift;
    unless ($sig->{key_id}) {
        my $sp = $sig->find_subpacket(16);
        $sig->{key_id} = $sp->{data};
    }
    $sig->{key_id};
}

sub find_subpacket {
    my $sig = shift;
    my($type) = @_;
    my @sp = (@{$sig->{subpackets_hashed}}, @{$sig->{subpackets_unhashed}});
    for my $sp (@sp) {
        return $sp if $sp->{type} == $type;
    }
}

sub new {
    my $class = shift;
    my $sig = bless { }, $class;
    $sig->init(@_);
}

sub init {
    my $sig = shift;
    my %param = @_;
    $sig->{subpackets_hashed} = [];
    $sig->{subpackets_unhashed} = [];
    if ((my $obj = $param{Data}) && (my $cert = $param{Key})) {
        $sig->{version} = $param{Version} || 4;
        $sig->{type} = $param{Type} || 0x00;
        $sig->{hash_alg} = $param{Digest} ? $param{Digest} :
            $sig->{version} == 4 ? DEFAULT_DIGEST : 1;
        $sig->{pk_alg} = $cert->key->alg_id;
        if ($sig->{version} < 4) {
            $sig->{timestamp} = time;
            $sig->{key_id} = $cert->key_id;
            $sig->{hash_len} = 5;
        }
        else {
            my $sp = Crypt::OpenPGP::Signature::SubPacket->new;
            $sp->{type} = 2;
            $sp->{data} = time;
            push @{ $sig->{subpackets_hashed} }, $sp;
            $sp = Crypt::OpenPGP::Signature::SubPacket->new;
            $sp->{type} = 16;
            $sp->{data} = $cert->key_id;
            push @{ $sig->{subpackets_unhashed} }, $sp;
        }
        my $hash = $sig->hash_data($obj);
        $sig->{chk} = substr $hash, 0, 2;
        my $sig_data = $cert->key->sign($hash,
            Crypt::OpenPGP::Digest->alg($sig->{hash_alg}));
        my @sig = $cert->key->sig_props;
        for my $e (@sig) {
            $sig->{$e} = $sig_data->{$e};
        }
    }
    $sig;
}

sub sig_trailer {
    my $sig = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;
    if ($sig->{version} < 4) {
        $buf->put_int8($sig->{type});
        $buf->put_int32($sig->{timestamp});
    }
    else {
        $buf->put_int8($sig->{version});
        $buf->put_int8($sig->{type});
        $buf->put_int8($sig->{pk_alg});
        $buf->put_int8($sig->{hash_alg});
        my $sp_data = $sig->_save_subpackets('hashed');
        $buf->put_int16(defined $sp_data ? length($sp_data) : 0);
        $buf->put_bytes($sp_data) if $sp_data;
        my $len = $buf->length;
        $buf->put_int8($sig->{version});
        $buf->put_int8(0xff);
        $buf->put_int32($len);
    }
    $buf->bytes;
}

sub parse {
    my $class = shift;
    my($buf) = @_;
    my $sig = $class->new;

    $sig->{version} = $buf->get_int8;
    if ($sig->{version} < 4) {
        $sig->{sig_data} = $buf->bytes($buf->offset+1, 5);
        $sig->{hash_len} = $buf->get_int8;
        return $class->error("Hash len $sig->{hash_len} != 5")
            unless $sig->{hash_len} == 5;
        $sig->{type} = $buf->get_int8;
        $sig->{timestamp} = $buf->get_int32;
        $sig->{key_id} = $buf->get_bytes(8);
        $sig->{pk_alg} = $buf->get_int8;
        $sig->{hash_alg} = $buf->get_int8;
    }
    else {
        $sig->{sig_data} = $buf->bytes($buf->offset-1, 6);
        $sig->{type} = $buf->get_int8;
        $sig->{pk_alg} = $buf->get_int8;
        $sig->{hash_alg} = $buf->get_int8;
        for my $h (qw( hashed unhashed )) {
            my $subpack_len = $buf->get_int16;
            my $sp_buf = $buf->extract($subpack_len);
            $sig->{sig_data} .= $sp_buf->bytes if $h eq 'hashed';
            while ($sp_buf->offset < $sp_buf->length) {
                my $len = $sp_buf->get_int8;
                if ($len >= 192 && $len < 255) {
                    my $len2 = $sp_buf->get_int8;
                    $len = (($len-192) << 8) + $len2 + 192;
                } elsif ($len == 255) {
                    $len = $sp_buf->get_int32;
                }
                my $this_buf = $sp_buf->extract($len);
                my $sp = Crypt::OpenPGP::Signature::SubPacket->parse($this_buf);
                push @{ $sig->{"subpackets_$h"} }, $sp;
            }
        }
    }
    $sig->{chk} = $buf->get_bytes(2);
    ## XXX should be Crypt::OpenPGP::Signature->new($sig->{pk_alg})?
    my $key = Crypt::OpenPGP::Key::Secret->new($sig->{pk_alg});
    my @sig = $key->sig_props;
    for my $e (@sig) {
        $sig->{$e} = $buf->get_mp_int;
    }
    $sig;
}

sub save {
    my $sig = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->put_int8($sig->{version});
    if ($sig->{version} < 4) {
        $buf->put_int8($sig->{hash_len});
        $buf->put_int8($sig->{type});
        $buf->put_int32($sig->{timestamp});
        $buf->put_bytes($sig->{key_id}, 8);
        $buf->put_int8($sig->{pk_alg});
        $buf->put_int8($sig->{hash_alg});
    }
    else {
        $buf->put_int8($sig->{type});
        $buf->put_int8($sig->{pk_alg});
        $buf->put_int8($sig->{hash_alg});
        for my $h (qw( hashed unhashed )) {
            my $sp_data = $sig->_save_subpackets($h);
            $buf->put_int16(defined $sp_data ? length($sp_data) : 0);
            $buf->put_bytes($sp_data) if $sp_data;
        }
    }
    $buf->put_bytes($sig->{chk}, 2);
    ## XXX should be Crypt::OpenPGP::Signature->new($sig->{pk_alg})?
    my $key = Crypt::OpenPGP::Key::Secret->new($sig->{pk_alg});
    my @sig = $key->sig_props;
    for my $e (@sig) {
        $buf->put_mp_int($sig->{$e});
    }
    $buf->bytes;
}

sub _save_subpackets {
    my $sig = shift;
    my($h) = @_;
    my @sp;
    return unless $sig->{"subpackets_$h"} &&
        (@sp = @{ $sig->{"subpackets_$h"} });
    my $sp_buf = Crypt::OpenPGP::Buffer->new;
    for my $sp (@sp) {
        my $data = $sp->save;
        my $len = length $data;
        if ($len < 192) {
            $sp_buf->put_int8($len);
        } elsif ($len < 8384) {
            $len -= 192;
            $sp_buf->put_int8( int($len / 256) + 192 );
            $sp_buf->put_int8( $len % 256 );
        } else {
            $sp_buf->put_int8(255);
            $sp_buf->put_int32($len);
        }
        $sp_buf->put_bytes($data);
    }
    $sp_buf->bytes;
}

sub hash_data {
    my $sig = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;
    my $type = ref($_[0]);
    if ($type eq 'Crypt::OpenPGP::Certificate') {
        my $cert = shift;
        $buf->put_int8(0x99);
        my $pk = $cert->public_cert->save;
        $buf->put_int16(length $pk);
        $buf->put_bytes($pk);

        if (@_) {
            if (ref($_[0]) eq 'Crypt::OpenPGP::UserID') {
                my $uid = shift;
                my $ud = $uid->save;
                if ($sig->{version} >= 4) {
                    $buf->put_int8(0xb4);
                    $buf->put_int32(length $ud);
                }
                $buf->put_bytes($ud);
            }
            elsif (ref($_[0]) eq 'Crypt::OpenPGP::Certificate') {
                my $subcert = shift;
                $buf->put_int8(0x99);
                my $k = $subcert->public_cert->save;
                $buf->put_int16(length $k);
                $buf->put_bytes($k);
            }
        }
    }
    elsif ($type eq 'Crypt::OpenPGP::Plaintext') {
        my $pt = shift;
        $buf->put_bytes($pt->data);
    }

    $buf->put_bytes($sig->sig_trailer);

    my $hash = Crypt::OpenPGP::Digest->new($sig->{hash_alg}) or
        return $sig->error( Crypt::OpenPGP::Digest->errstr );
    $hash->hash($buf->bytes);
}

1;
