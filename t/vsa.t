#!/usr/bin/perl

# Test VSA packing and unpacking

# $Id: vsa.t,v 1.1 2007/04/21 18:04:17 lem Exp $


use IO::File;
use Test::More 'no_plan';
use Net::Radius::Packet;
use Net::Radius::Dictionary;

# Init the dictionary for our test run...
BEGIN {
    my $fh = new IO::File "dict.$$", ">";
    print $fh <<EOF;
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	NAS-Port		5	integer
ATTRIBUTE	Service-Type		6	integer

VENDOR		Cisco-VPN3000	3076

ATTRIBUTE CVPN3000-Access-Hours			1	string Cisco-VPN3000
ATTRIBUTE CVPN3000-Simultaneous-Logins		2	integer Cisco-VPN3000
EOF

    close $fh;
};

END { unlink 'dict.' . $$; }

my $d = new Net::Radius::Dictionary "dict.$$";
isa_ok($d, 'Net::Radius::Dictionary');

# Build a request and test it is ok - We're leaving out the
# authenticator calculation

my $p = new Net::Radius::Packet $d;
isa_ok($p, 'Net::Radius::Packet');
$p->set_identifier(42);
$p->set_authenticator("\x66" x 16);
$p->set_code("Access-Accept");
$p->set_attr("User-Name" => 'foo');
$p->set_attr('Service-Type' => 'Framed-User');
$p->set_attr('NAS-Port' => '42');
$p->set_vsattr('Cisco-VPN3000', 'CVPN3000-Access-Hours', "Access-Hours");
$p->set_vsattr('Cisco-VPN3000', 'CVPN3000-Simultaneous-Logins', 63);

my $q = new Net::Radius::Packet $d, $p->pack;
isa_ok($q, 'Net::Radius::Packet');

is($p->code, 'Access-Accept', "Correct packet code");
is($p->attr('User-Name'), 'foo', "Correct User-Name");
is($p->attr('Service-Type'), 'Framed-User', "Correct Framed-User");
is($p->attr('NAS-Port'), 42, "Correct NAS-Port");
is($p->attr('User-Name'), 'foo', "Correct User-Name");
is(ref($p->vsattr('Cisco-VPN3000', 'CVPN3000-Access-Hours')), 
   'ARRAY', "Correct type for string VSA");
is($p->vsattr('Cisco-VPN3000', 'CVPN3000-Access-Hours')->[0], 
   'Access-Hours', "Correct string VSA");
is(ref($p->vsattr('Cisco-VPN3000', 'CVPN3000-Simultaneous-Logins')), 
   'ARRAY', "Correct type for integer VSA");
is($p->vsattr('Cisco-VPN3000', 'CVPN3000-Simultaneous-Logins')->[0], 
   '63', "Correct integer VSA");

