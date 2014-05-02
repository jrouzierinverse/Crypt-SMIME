# -*- perl -*-
use strict;
use warnings;
use ExtUtils::PkgConfig ();
use File::Spec;
use File::Temp qw(tempfile);
use Test::More tests => 13;

my ($key, $crt);
do {
    my $OPENSSL = ExtUtils::PkgConfig->variable('openssl', 'prefix') . '/bin/openssl';
    if (-x $OPENSSL) {
        diag "Using `$OPENSSL' to generate a keypair";
    }
    else {
        BAIL_OUT(q{Executable `openssl' was not found});
    }

    my ($conf_fh, $conf_file) = tempfile(UNLINK => 1);
    print {$conf_fh} <<'EOF';
[ req ]
distinguished_name     = req_distinguished_name
attributes             = req_attributes
prompt                 = no
[ req_distinguished_name ]
C                      = AU
ST                     = Some-State
L                      = Test Locality
O                      = Organization Name
OU                     = Organizational Unit Name
CN                     = Common Name
emailAddress           = test@email.address
[ req_attributes ]
EOF
    close $conf_fh;

    my $DEVNULL = File::Spec->devnull();
    my (undef, $key_file) = tempfile(UNLINK => 1);
    my (undef, $csr_file) = tempfile(UNLINK => 1);
    my (undef, $crt_file) = tempfile(UNLINK => 1);

    system(qq{$OPENSSL genrsa -out $key_file >$DEVNULL 2>&1}) and die $!;
    system(qq{$OPENSSL req -new -key $key_file -out $csr_file -config $conf_file >$DEVNULL 2>&1}) and die $!;
    system(qq{$OPENSSL x509 -in $csr_file -out $crt_file -req -signkey $key_file -set_serial 1 >$DEVNULL 2>&1}) and die $!;

    $key = do {
        local $/;
        open my $fh, '<', $key_file or die $!;
        scalar <$fh>;
    };
    $crt = do {
        local $/;
        open my $fh, '<', $crt_file or die $!;
        scalar <$fh>;
    };
};

BEGIN {
    use_ok('Crypt::SMIME');
}

my $password = '';
my $src_mime = "Content-Type: text/plain\r\n"
             . "Subject: S/MIME test.\r\n"
             . "From: alice\@example.com\r\n"
             . "To:   bob\@example.org\r\n"
             . "\r\n"
             . "test message.\r\n";
my $verify = "Content-Type: text/plain\r\n"
           . "Subject: S/MIME test.\r\n"
           . "\r\n"
           . "test message.\r\n";
my $verify_header = "Subject: S/MIME test.\r\n"
                  . "From: alice\@example.com\r\n"
                  . "To:   bob\@example.org\r\n";
my $signed;
my $encrypted;

{
  # smime-sign.
  my $smime = Crypt::SMIME->new();
  ok($smime, "new instance of Crypt::SMIME");

  $smime->setPrivateKey($key, $crt, $password);
  $signed = $smime->sign($src_mime); # $src_mimeはMIMEメッセージ文字列
  ok($signed, 'got anything from $smime->sign');
  my @lf = $signed=~/\n/g;
  my @crlf = $signed=~/\r\n/g;
  is(scalar@crlf,scalar@lf,'all \n in signed are part of \r\n');
  #diag($signed);

  # prepare/sign-only
  my ($prepared,$header) = $smime->prepareSmimeMessage($src_mime);
  is($prepared,$verify,"prepared mime message");
  is($header,$verify_header,"outer headers of prepared mime message");
  ok(index($signed,$prepared)>=0, 'prepared message is apprers in signed message too');
  ok(index($signed,$header)>=0, 'outer headers of prepared message is apprers in signed message too');

  my $signed_only = $smime->signonly($src_mime);
  ok($signed_only, 'got anything from $smime->signonly');
  #diag($signed_only);
  @lf = $signed_only=~/\n/g;
  @crlf = $signed_only=~/\r\n/g;
  is(scalar@crlf,scalar@lf,'all \n in signed_only are part of \r\n');
}

{
  # smime-encrypt.
  my $smime = Crypt::SMIME->new();
  $smime->setPublicKey($crt);
  $encrypted = $smime->encrypt($signed);
  ok($encrypted, 'got anything from $smime->encrypt');
}

{
  # smime-decrypt.
  my $smime = Crypt::SMIME->new();
  $smime->setPrivateKey($key, $crt, $password);
  my $decrypted = $smime->decrypt($encrypted);
  ok($decrypted, 'got anything from $smime->decrypt');

  # and verify.
  $smime->setPublicKey($crt);
  is($smime->check($decrypted),$verify, 'verify result of decrypt.');
}
