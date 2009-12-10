use strict;
use Test::More tests => 20;
use Test::Exception;

use Crypt::OpenPGP;
use Crypt::OpenPGP::Config;

use vars qw( $SAMPLES );
unshift @INC, 't/';
require 'test-common.pl';
use File::Spec;

{
    diag 'GnuPG config';

    my $cfg_file = File::Spec->catfile( $SAMPLES, 'cfg.gnupg' );

    my $cfg = Crypt::OpenPGP::Config->new;
    isa_ok $cfg, 'Crypt::OpenPGP::Config';
    lives_ok { $cfg->read_config( 'GnuPG', $cfg_file ) }
        'can read GnuPG config file';

    # Test standard str directive
    is $cfg->get( 'Digest' ), 'MD5', 'Digest == MD5';
    $cfg->set( 'Digest', 'SHA1' );
    is $cfg->get( 'Digest' ), 'SHA1', 'Digest == SHA1';

    # Test standard bool directive, no arg (eg. 'armor')
    is $cfg->get( 'Armour' ), 1, 'Armour == 1';
    $cfg->set( 'Armour', 0 );
    is $cfg->get( 'Armour' ), 0, 'Armour == 0';

    # Test special Cipher directive (eg. 'cipher-algo TWOFISH')
    is $cfg->get( 'Cipher' ), 'Twofish', 'cipher-algo -> Cipher';

    # Test special Compress directive
    is $cfg->get( 'Compress' ), 'Zlib', 'compress-algo -> Compress';

    # Test that config file gets read correctly when passed to
    # constructor.
    my $pgp = Crypt::OpenPGP->new( ConfigFile => $cfg_file, Compat => 'GnuPG' );
    isa_ok $pgp, 'Crypt::OpenPGP';
    isa_ok $pgp->{cfg}, 'Crypt::OpenPGP::Config';
    is $pgp->{cfg}->get( 'Armour' ), 1, 'Armour == 1';
}

{
    diag 'pgp2 config';

    my $cfg_file = File::Spec->catfile( $SAMPLES, 'cfg.pgp2' );

    my $cfg = Crypt::OpenPGP::Config->new;
    isa_ok $cfg, 'Crypt::OpenPGP::Config';
    lives_ok { $cfg->read_config( 'PGP2', $cfg_file ) }
        'can read pgp2 config file';

    # Test standard str directive
    is $cfg->get( 'PubRing' ), 'foo.pubring', 'Pubring == foo.pubring';
    $cfg->set( 'PubRing', 'bar.pubring' );
    is $cfg->get( 'PubRing' ), 'bar.pubring', 'Pubring == bar.pubring';

    # Test standard bool directive, with arg (eg. 'Armor on')
    is $cfg->get( 'Armour' ), 1, 'Armour == 1';
    $cfg->set( 'Armour', 0 );
    is $cfg->get( 'Armour' ), 0, 'Armour == 0';

    # Test that config file gets read correctly when passed to
    # constructor.
    my $pgp = Crypt::OpenPGP->new( ConfigFile => $cfg_file, Compat => 'PGP2' );
    isa_ok $pgp, 'Crypt::OpenPGP';
    isa_ok $pgp->{cfg}, 'Crypt::OpenPGP::Config';
    is $pgp->{cfg}->get( 'Armour' ), 1, 'Armour == 1';
}