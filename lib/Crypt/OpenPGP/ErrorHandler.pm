# $Id: ErrorHandler.pm,v 1.4 2001/07/25 20:52:39 btrott Exp $

package Crypt::OpenPGP::ErrorHandler;
use strict;

use vars qw( $ERROR );

sub new    { bless {}, shift }
sub error  {
    my $msg = $_[1];
    $msg .= "\n" unless $msg =~ /\n$/;
    if (ref($_[0])) {
        $_[0]->{_errstr} = $msg;
    } else {
        $ERROR = $msg;
    }
    return;
 }
sub errstr { ref($_[0]) ? $_[0]->{_errstr} : $ERROR }

1;
