# $Id: 00-compile.t,v 1.1 2001/07/21 08:09:31 btrott Exp $

my $loaded;
BEGIN { print "1..1\n" }
use Crypt::OpenPGP;
$loaded++;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded }
