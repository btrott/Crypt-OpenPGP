# $Id: Certificate.pm,v 1.9 2001/07/26 18:28:54 btrott Exp $

package Crypt::OpenPGP::Certificate;
use strict;

use Crypt::OpenPGP::S2k;
use Crypt::OpenPGP::Key::Public;
use Crypt::OpenPGP::Key::Secret;
use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::Util qw( mp2bin bin2mp bitsize );
use Crypt::OpenPGP::Constants qw( DEFAULT_CIPHER 
                                  PGP_PKT_PUBLIC_KEY
                                  PGP_PKT_PUBLIC_SUBKEY
                                  PGP_PKT_SECRET_KEY
                                  PGP_PKT_SECRET_SUBKEY );
use Crypt::OpenPGP::Cipher;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

{
    my @PKT_TYPES = (
        PGP_PKT_PUBLIC_KEY,
        PGP_PKT_PUBLIC_SUBKEY,
        PGP_PKT_SECRET_KEY,
        PGP_PKT_SECRET_SUBKEY
    );
    sub pkt_type {
        my $cert = shift;
        $PKT_TYPES[ ($cert->{is_secret} << 1) | $cert->{is_subkey} ];
    }
}

sub new {
    my $class = shift;
    my $cert = bless { }, $class;
    $cert->init(@_);
}

sub init {
    my $cert = shift;
    my %param = @_;
    if (my $key = $param{Key}) {
        $cert->{version} = $param{Version} || 4;
        $cert->{key} = $key;
        $cert->{is_secret} = $key->is_secret;
        $cert->{is_subkey} = $param{Subkey} || 0;
        $cert->{timestamp} = time;
        $cert->{pk_alg} = $key->alg_id;
        if ($cert->{version} < 4) {
            $cert->{validity} = $param{Validity} || 0;
            $key->alg eq 'RSA' or
                return (ref $cert)->error("Version 3 keys must be RSA");
        }
        $cert->{s2k} = Crypt::OpenPGP::S2k->new('Salt_Iter');

        if ($cert->{is_secret}) {
            $param{Passphrase} or
                return (ref $cert)->error("Need a Passphrase to lock key");
            $cert->{cipher} = $param{Cipher} || DEFAULT_CIPHER;
            $cert->lock($param{Passphrase});
        }
    }
    $cert;
}

sub type { $_[0]->{type} }
sub version { $_[0]->{version} }
sub timestamp { $_[0]->{timestamp} }
sub validity { $_[0]->{validity} }
sub pk_alg { $_[0]->{pk_alg} }
sub key { $_[0]->{key} }
sub is_secret { $_[0]->{key}->is_secret }
sub is_subkey { $_[0]->{is_subkey} }
sub is_protected { $_[0]->{is_protected} }

sub public_cert {
    my $cert = shift;
    return $cert unless $cert->is_secret;
    my $pub = (ref $cert)->new;
    for my $f (qw( version timestamp pk_alg is_subkey )) {
        $pub->{$f} = $cert->{$f};
    }
    $pub->{validity} = $cert->{validity} if $cert->{version} < 4;
    $pub->{key} = $cert->{key}->public_key;
    $pub;
}

sub key_id {
    my $cert = shift;
    unless ($cert->{key_id}) {
        if ($cert->{version} < 4) {
            $cert->{key_id} = substr(mp2bin($cert->{key}->n), -8);
        }
        else {
            $cert->{key_id} = substr($cert->fingerprint, -8);
        }
    }
    $cert->{key_id};
}

sub fingerprint {
    my $cert = shift;
    unless ($cert->{fingerprint}) {
        if ($cert->{version} < 4) {
            my $dgst = Crypt::OpenPGP::Digest->new('MD5');
            $cert->{fingerprint} = $dgst->hash($cert->{key}->n.$cert->{key}->e);
        }
        else {
            my $data = $cert->public_cert->save;
            $cert->{fingerprint} = _gen_v4_fingerprint($data);
        }
    }
    $cert->{fingerprint};
}

sub _gen_v4_fingerprint {
    my($data) = @_;
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->put_int8(0x99);
    $buf->put_int16(length $data);
    $buf->put_bytes($data);
    my $dgst = Crypt::OpenPGP::Digest->new('SHA1');
    $dgst->hash($buf->bytes);
}

sub parse {
    my $class = shift;
    my($buf, $secret, $subkey) = @_;
    my $cert = $class->new;
    $cert->{is_secret} = $secret;
    $cert->{is_subkey} = $subkey;

    $cert->{version} = $buf->get_int8;
    $cert->{timestamp} = $buf->get_int32;
    if ($cert->{version} < 4) {
        $cert->{validity} = $buf->get_int16;
    }
    $cert->{pk_alg} = $buf->get_int8;

    my $key_class = 'Crypt::OpenPGP::Key::' . ($secret ? 'Secret' : 'Public');
    my $key = $cert->{key} = $key_class->new($cert->{pk_alg}) or
        return $class->error("Key creation failed: " . $key_class->errstr);

    my @pub = $key->public_props;
    for my $e (@pub) {
        $key->$e($buf->get_mp_int);
    }

    if ($cert->{version} >= 4) {
        my $data = $buf->bytes(0, $buf->offset);
        $cert->{fingerprint} = _gen_v4_fingerprint($data);
    }

    if ($secret) {
        $cert->{cipher} = $buf->get_int8;
        if ($cert->{cipher}) {
            $cert->{is_protected} = 1;
            if ($cert->{cipher} == 255) {
                $cert->{cipher} = $buf->get_int8;
                $cert->{s2k} = Crypt::OpenPGP::S2k->new('', $buf);
            }
            else {
                $cert->{s2k} = Crypt::OpenPGP::S2k->new('Simple');
                $cert->{s2k}->set_hash('MD5');
            }

            $cert->{iv} = $buf->get_bytes(8);
        }

        if ($cert->{is_protected}) {
            if ($cert->{version} < 4) {
                $cert->{encrypted} = {};
                my @sec = $key->secret_props;
                for my $e (@sec) {
                    my $h = $cert->{encrypted}{"${e}h"} = $buf->get_bytes(2);
                    $cert->{encrypted}{"${e}b"} =
                        $buf->get_bytes(int((unpack('n', $h)+7)/8));
                }
                $cert->{csum} = $buf->get_int16;
            }
            else {
                $cert->{encrypted} =
                    $buf->get_bytes($buf->length - $buf->offset);
            }
        }
        else {
            my @sec = $key->secret_props;
            for my $e (@sec) {
                $key->$e($buf->get_mp_int);
            }
        }
    }

    $cert;
}

sub save {
    my $cert = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;

    $buf->put_int8($cert->{version});
    $buf->put_int32($cert->{timestamp});
    if ($cert->{version} < 4) {
        $buf->put_int16($cert->{validity});
    }
    $buf->put_int8($cert->{pk_alg});

    my $key = $cert->{key};
    my @pub = $key->public_props;
    for my $e (@pub) {
        $buf->put_mp_int($key->$e());
    }

    if ($cert->{key}->is_secret) {
        if ($cert->{cipher}) {
            $buf->put_int8(255);
            $buf->put_int8($cert->{cipher});
            $buf->append($cert->{s2k}->save->bytes);
            $buf->put_bytes($cert->{iv});

            if ($cert->{version} < 4) {
                my @sec = $key->secret_props;
                for my $e (@sec) {
                    $buf->put_bytes($cert->{encrypted}{"${e}h"});
                    $buf->put_bytes($cert->{encrypted}{"${e}b"});
                }
                $buf->put_int16($cert->{csum});
            }
            else {
                $buf->put_bytes($cert->{encrypted});
            }
        }
        else {
            my @sec = $key->secret_props;
            for my $e (@sec) {
                $key->$e($buf->get_mp_int);
            }
        }
    }
    $buf->bytes;
}

sub v3_checksum {
    my $cert = shift;
    my $k = $cert->{encrypted};
    my $sum = 0;
    my @sec = $cert->{key}->secret_props;
    for my $e (@sec) {
        $sum += unpack '%16C*', $k->{"${e}h"};
        $sum += unpack '%16C*', $k->{"${e}b"};
    }
    $sum & 0xFFFF;
}

sub unlock {
    my $cert = shift;
    return 1 unless $cert->{is_secret} && $cert->{is_protected};
    my($passphrase) = @_;
    my $cipher = Crypt::OpenPGP::Cipher->new($cert->{cipher});
    my $key = $cert->{s2k}->generate($passphrase, $cipher->key_len);
    $cipher->init($key, $cert->{iv});
    my @sec = $cert->{key}->secret_props;
    if ($cert->{version} < 4) {
        my $k = $cert->{encrypted};
        my $r = {};
        for my $e (@sec) {
            $r->{$e} = $k->{"${e}b"};
            $k->{"${e}b"} = $cipher->decrypt($r->{$e});
        }
        unless ($cert->{csum} == $cert->v3_checksum) {
            $k->{"${_}b"} = $r->{$_} for @sec;
            return $cert->error("Bad checksum");
        }
        for my $e (@sec) {
            $cert->{key}->$e(bin2mp($k->{"${e}b"}));
        }
        unless ($cert->{key}->check) {
            $k->{"${_}b"} = $r->{$_} for @sec;
            return $cert->error("p*q != n");
        }
    }
    else {
        my $decrypted = $cipher->decrypt($cert->{encrypted});
        my $csum = unpack "n", substr $decrypted, -2, 2, '';
        my $gen_csum = unpack '%16C*', $decrypted;
        unless ($csum == $gen_csum) {
            return $cert->error("Bad checksum");
        }
        my $buf = Crypt::OpenPGP::Buffer->new;
        $buf->append($decrypted);
        for my $e (@sec) {
            $cert->{key}->$e( $buf->get_mp_int );
        }
    }

    $cert->{is_protected} = 0;

    1;
}

sub lock {
    my $cert = shift;
    return if !$cert->{is_secret} || $cert->{is_protected};
    my($passphrase) = @_;
    my $cipher = Crypt::OpenPGP::Cipher->new($cert->{cipher});
    my $sym_key = $cert->{s2k}->generate($passphrase, $cipher->key_len);
    require Crypt::Random;
    $cert->{iv} = Crypt::Random::makerandom_octet( Length => 8 );
    $cipher->init($sym_key, $cert->{iv});
    my @sec = $cert->{key}->secret_props;
    if ($cert->{version} < 4) {
        my $k = $cert->{encrypted} = {};
        my $key = $cert->key;
        for my $e (@sec) {
            $k->{"${e}b"} = mp2bin($key->$e());
            $k->{"${e}h"} = pack 'n', bitsize($key->$e());
        }
        $cert->{csum} = $cert->v3_checksum;
        for my $e (@sec) {
            $k->{"${e}b"} = $cipher->encrypt( $k->{"${e}b"} );
        }
    }
    else {
        my $buf = Crypt::OpenPGP::Buffer->new;
        for my $e (@sec) {
            $buf->put_mp_int($cert->{key}->$e());
        }
        my $cnt = $buf->bytes;
        $cnt .= pack 'n', unpack '%16C*', $cnt;
        $cert->{encrypted} = $cipher->encrypt($cnt);
    }

    $cert->{is_protected} = 1;
    1;
}

1;
