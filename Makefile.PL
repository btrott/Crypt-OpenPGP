use inc::Module::Install;
name 'Crypt-OpenPGP';
all_from 'lib/Crypt/OpenPGP.pm';
readme_from 'lib/Crypt/OpenPGP.pm';

# Core requirements.
requires 'Data::Buffer' => '0.04';
requires 'MIME::Base64';
requires 'Math::Pari';
requires 'Compress::Zlib';
requires 'LWP::UserAgent';
requires 'URI::Escape';
requires 'Crypt::DSA';
requires 'Crypt::RSA';
requires 'File::HomeDir';

# PGP2 compat.
requires 'Crypt::IDEA';
requires 'Digest::MD5';

# PGP5 compat.
requires 'Crypt::DES_EDE3';
requires 'Digest::SHA1';

# GnuPG compat.
requires 'Crypt::Rijndael';
requires 'Crypt::CAST5_PP';
requires 'Crypt::RIPEMD160';

# Other ciphers.
requires 'Crypt::Blowfish';
requires 'Crypt::Twofish';

test_requires 'Test::More';
test_requires 'Test::Exception';

use_test_base;
auto_include_deps;
author_tests('xt');
auto_set_repository;
WriteAll;