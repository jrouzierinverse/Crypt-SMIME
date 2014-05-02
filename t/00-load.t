#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'RPC::Ridill::Client' );
}

diag( "Testing RPC::Ridill::Client $RPC::Ridill::Client::VERSION, Perl $], $^X" );
