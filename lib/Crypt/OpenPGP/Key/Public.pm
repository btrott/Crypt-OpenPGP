# $Id: Public.pm,v 1.3 2001/07/21 06:54:28 btrott Exp $

package Crypt::OpenPGP::Key::Public;
use strict;

use Crypt::OpenPGP::Key;
use Crypt::OpenPGP::ErrorHandler;
use base qw( Crypt::OpenPGP::Key Crypt::OpenPGP::ErrorHandler );

sub all_props { $_[0]->public_props }
sub is_secret { 0 }
sub public_key { $_[0] }

1;
