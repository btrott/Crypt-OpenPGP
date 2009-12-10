my $loaded;
BEGIN { print "1..1\n" }
use Crypt::OpenPGP;
$loaded++;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded }
