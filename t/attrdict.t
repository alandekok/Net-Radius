#!/usr/bin/perl

# Test the parsing of individual attributes

# $Id: attrdict.t,v 1.1 2003/10/16 20:10:24 lem Exp $

use IO::File;
use Test::More;
use Data::Dumper;
use Net::Radius::Dictionary;

my $dictfile = "dict$$.tmp";

END 
{
    unlink $dictfile;
};

my @dicts = ();
my @refs = ();

{
    local $/ = "EOD\n";
    @dicts = map { (s/EOD\n$//, $_)[1] } <DATA>;
};

$refs[0] = bless {
    'vsattr'	=> {},
    'rattr'	=> {},
    'vendors'	=> {},
    'rvsaval'	=> {},
    'val'	=> {},
    'rvsattr'	=> {},
    'attr'	=> {},
    'rval'	=> {},
    'vsaval'	=> {}
}, 'Net::Radius::Dictionary';

$refs[1] = bless {
    'vsattr' => {
	'9' => {
	    'cisco-avpair' => ['1', 'string' ],
	    'cisco-thing' => ['2', 'string' ]
	    }
    },
    'rattr' => {
	'1' => ['user-name', 'string'],
	'23' => ['framed-ipx-network', 'ipaddr'],
	'10' => ['framed-routing', 'integer']
	},
	    'vendors' => {
		'cisco' => '9'
		},
		    'rvsaval' => {},
		    'val' => {},
		    'rvsattr' => {
			'9' => {
			    '1' => ['cisco-avpair', 'string'],
			    '2' => ['cisco-thing', 'string']
			    }
		    },
    'attr' => {
	'framed-ipx-network' => ['23', 'ipaddr'],
	'framed-routing' => ['10', 'integer'],
	'user-name' => ['1', 'string']
	},
	    'rval' => {},
	    'vsaval' => {}
}, 'Net::Radius::Dictionary';

sub _write
{
    my $dict = shift;
    my $fh = new IO::File;
    $fh->open($dictfile, "w") or diag "Failed to write dict $dictfile: $!";
    print $fh $dict;
    $fh->close;
}

plan tests => 20 * scalar @dicts;

for my $i (0 .. $#dicts)
{

    _write $dicts[$i];

    my $d;

    eval { $d = new Net::Radius::Dictionary $dictfile; };

    isa_ok($d, 'Net::Radius::Dictionary');
    ok(!$@, "No errors during parse");
    diag $@ if $@;
    
    for my $k (keys %{$refs[$i]})
    {
	ok(exists $d->{$k}, "Element $k exists in the object");
	is_deeply($d->{$k}, $refs[$i]->{$k}, "Same contents in element $k");
    }
}

__END__
# Empty dictionary
EOD
# Sample dictionary
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	Framed-Routing		10	integer
ATTRIBUTE	Framed-IPX-Network	23	ipaddr
VENDOR		Cisco		9
ATTRIBUTE	Cisco-AVPair		1	string		Cisco
VENDORATTR	9	cisco-thing	2	string
