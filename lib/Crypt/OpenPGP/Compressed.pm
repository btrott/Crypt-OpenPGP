# $Id: Compressed.pm,v 1.3 2001/07/27 21:21:14 btrott Exp $

package Crypt::OpenPGP::Compressed;
use strict;

use Compress::Zlib;
use Crypt::OpenPGP::Buffer;
use Crypt::OpenPGP::Constants qw( DEFAULT_COMPRESS );
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::ErrorHandler );

use vars qw( %ALG %ALG_BY_NAME );
%ALG = ( 1 => 'ZIP', 2 => 'Zlib' );
%ALG_BY_NAME = map { $ALG{$_} => $_ } keys %ALG;

sub alg { $ALG{$_[1]} || $_[1] }
sub alg_id { $ALG_BY_NAME{$_[1]} || $_[1] }

sub new {
    my $comp = bless { }, shift;
    $comp->init(@_);
}

sub init {
    my $comp = shift;
    my %param = @_;
    if (my $data = $param{Data}) {
        $comp->{alg} = $param{Alg} || DEFAULT_COMPRESS;
        my %args;
        if ($comp->{alg} == 1) {
            %args = (-WindowBits => -13, -MemLevel => 8);
        }
        my($d, $status, $compressed);
        ($d, $status) = deflateInit(\%args);
        return (ref $comp)->error("Zlib deflateInit error: $status")
            unless $status == Compress::Zlib::Z_OK();
        {
            my($output, $out);
            ($output, $status) = $d->deflate($data);
            last unless $status == Compress::Zlib::Z_OK();
            ($out, $status) = $d->flush();
            last unless $status == Compress::Zlib::Z_OK();
            $compressed = $output . $out;
        }
        return (ref $comp)->error("Zlib deflation error: $status")
            unless defined $compressed;
        $comp->{data} = $compressed;
    }
    $comp;
}

sub parse {
    my $class = shift;
    my($buf) = @_;
    my $comp = $class->new;
    $comp->{alg} = $buf->get_int8;
    $comp->{data} = $buf->get_bytes($buf->length - $buf->offset);
    $comp;
}

sub save {
    my $comp = shift;
    my $buf = Crypt::OpenPGP::Buffer->new;
    $buf->put_int8($comp->{alg});
    $buf->put_bytes($comp->{data});
    $buf->bytes;
}

sub decompress {
    my $comp = shift;
    my %args;
    if ($comp->{alg} == 1) {
        %args = (-WindowBits => -13);
    }
    my($i, $status, $out);
    ($i, $status) = inflateInit(\%args);
    return $comp->error("Zlib inflateInit error: $status")
        unless $status == Compress::Zlib::Z_OK();
    ($out, $status) = $i->inflate($comp->{data});
    return $comp->error("Zlib inflate error: $status")
        unless defined $out;
    $out;
}

1;
