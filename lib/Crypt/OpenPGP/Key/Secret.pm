# $Id: Secret.pm,v 1.3 2001/08/09 04:26:33 btrott Exp $

package Crypt::OpenPGP::Key::Secret;
use strict;

use Crypt::OpenPGP::Key;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::Key Crypt::OpenPGP::ErrorHandler );

sub is_secret { 1 }
sub all_props { ($_[0]->public_props, $_[0]->secret_props) }

sub public_key {
    my $key = shift;
    my @pub = $key->public_props;
    my $pub = Crypt::OpenPGP::Key::Public->new($key->alg);
    for my $e (@pub) {
        $pub->$e($key->$e());
    }
    $pub;
}

1;
