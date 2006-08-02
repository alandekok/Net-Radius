package Net::Radius::Packet;

use strict;
require Exporter;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $VSA);
@ISA       = qw(Exporter);
@EXPORT    = qw(auth_resp);
@EXPORT_OK = qw( );

$VERSION = '1.45';

$VSA = 26;			# Type assigned in RFC2138 to the 
				# Vendor-Specific Attributes

# Be shure our dictionaries are current
use Net::Radius::Dictionary 1.1;
use Carp;
use Socket;
use Digest::MD5;

my (%unkvprinted, %unkgprinted);

sub new {
  my ($class, $dict, $data) = @_;
  my $self = { unknown_entries => 1 };
  bless $self, $class;
  $self->set_dict($dict) if defined($dict);
  $self->unpack($data) if defined($data);
  return $self;
}

# Set the dictionary
sub set_dict {
  my ($self, $dict) = @_;
  $self->{Dict} = $dict;
}

# Functions for accessing data structures
sub code          { $_[0]->{Code};          }
sub identifier    { $_[0]->{Identifier};    }
sub authenticator { $_[0]->{Authenticator}; }

sub set_code          { $_[0]->{Code} = $_[1];          }
sub set_identifier    { $_[0]->{Identifier} = $_[1];    }
sub set_authenticator { $_[0]->{Authenticator} = $_[1]; }

sub attributes { keys %{$_[0]->{Attributes}};        }
sub attr     { $_[0]->{Attributes}->{$_[1]};         }
sub set_attr { $_[0]->{Attributes}->{$_[1]} = $_[2]; }
sub unset_attr { delete $_[0]->{Attributes}->{$_[1]}; }

sub vendors      { keys %{$_[0]->{VSAttributes}};                          }
sub vsattributes { keys %{$_[0]->{VSAttributes}->{$_[1]}};                 }
sub vsattr       { $_[0]->{VSAttributes}->{$_[1]}->{$_[2]};                }
sub set_vsattr   { push @{$_[0]->{VSAttributes}->{$_[1]}->{$_[2]}}, $_[3]; }

sub show_unknown_entries { $_[0]->{unknown_entries} = $_[1]; }

# Decode the password
sub password {
  my ($self, $secret) = @_;
  my $lastround = $self->authenticator;
  my $pwdin = $self->attr("User-Password") || $self->attr("Password");
  my $pwdout = ""; # avoid possible undef warning
  for (my $i = 0; $i < length($pwdin); $i += 16) {
    $pwdout .= substr($pwdin, $i, 16) ^ Digest::MD5::md5($secret . $lastround);
    $lastround = substr($pwdin, $i, 16);
  }
  $pwdout =~ s/\000*$// if $pwdout;
    substr($pwdout,length($pwdin)) = "" 
	unless length($pwdout) <= length($pwdin);
  return $pwdout;
}

# Encode the password
sub set_password {
  my ($self, $pwdin, $secret) = @_;
  my $lastround = $self->authenticator;
  my $pwdout = ""; # avoid possible undef warning
  $pwdin .= "\000" x (15-(15 + length $pwdin)%16);     # pad to 16n bytes

  for (my $i = 0; $i < length($pwdin); $i += 16) {
    $lastround = substr($pwdin, $i, 16) 
      ^ Digest::MD5::md5($secret . $lastround);
    $pwdout .= $lastround;
  }
  $self->set_attr("User-Password" => $pwdout);
}

# Set response authenticator in binary packet
sub auth_resp {
  my $new = $_[0];
  substr($new, 4, 16) = Digest::MD5::md5($_[0] . $_[1]);
  return $new;
}

# Utility functions for printing/debugging
sub pdef { defined $_[0] ? $_[0] : "UNDEF"; }
sub pclean {
  my $str = $_[0];
  $str =~ s/([\000-\037\177-\377])/<${\ord($1)}>/g;
  return $str;
}

sub dump {
    print str_dump(@_);
}

sub str_dump {
  my $self = shift;
  my $ret = '';
  $ret .= "*** DUMP OF RADIUS PACKET ($self)\n";
  $ret .= "Code:       ". pdef($self->{Code}). "\n";
  $ret .= "Identifier: ". pdef($self->{Identifier}). "\n";
  $ret .= "Authentic:  ". pclean(pdef($self->{Authenticator})). "\n";
  $ret .= "Attributes:\n";
  foreach my $attr ($self->attributes) {
    $ret .= sprintf("  %-20s %s\n", $attr . ":" , 
		    pclean(pdef($self->attr($attr))));
  }
  foreach my $vendor ($self->vendors) {
    $ret .= "VSA for vendor $vendor\n";
    foreach my $attr ($self->vsattributes($vendor)) {
      $ret .= sprintf("    %-20s %s\n", $attr . ":" ,
		      pclean(join("|", @{$self->vsattr($vendor, $attr)})));
    }
  }
  $ret .= "*** END DUMP\n";
  return $ret;
}

sub pack {
  my $self = shift;
  my $hdrlen = 1 + 1 + 2 + 16;    # Size of packet header
  my $p_hdr  = "C C n a16 a*";    # Pack template for header
  my $p_attr = "C C a*";          # Pack template for attribute
  my $p_vsa  = "C C N C C a*";    

  # XXX - The spec says that a
  # 'Vendor-Type' must be included
  # but there are no documented definitions
  # for this! We'll simply skip this value

  my $p_vsa_3com  = "C C N N a*";    

  my %codes  = ('Access-Request'      => 1,  'Access-Accept'      => 2,
		'Access-Reject'       => 3,  'Accounting-Request' => 4,
		'Accounting-Response' => 5,  'Access-Challenge'   => 11,
		'Status-Server'       => 12, 'Status-Client'      => 13);
  my $attstr = "";                # To hold attribute structure
  # Define a hash of subroutine references to pack the various data types
  my %packer = (
		"octets" => sub { return $_[0]; },
		"string" => sub { return $_[0]; },
		"integer" => sub {
		    return pack "N", $self->{Dict}->attr_has_val($_[1]) ?
			$self->{Dict}->val_num(@_[1, 0]) : $_[0];
		},
		"ipaddr" => sub {
		    return inet_aton($_[0]);
		},
		"time" => sub {
		    return pack "N", $_[0];
		},
		"date" => sub {
		    return pack "N", $_[0];
		});

  my %vsapacker = (
		   "octets" => sub { return $_[0]; },
		   "string" => sub { return $_[0]; },
		   "integer" => sub {
		       return pack "N", 
		       $self->{Dict}->vsattr_has_val($_[2], $_[1]) ?
			   $self->{Dict}->vsaval_num(@_[2, 1, 0]) : $_[0];
		   },
		   "ipaddr" => sub {
		       return inet_aton($_[0]);
		   },
		   "time" => sub {
		       return pack "N", $_[0];
		   },
		   "date" => sub {
		       return pack "N", $_[0];
		   });
    
  # Pack the attributes
  foreach my $attr ($self->attributes) {

      if (! defined $self->{Dict}->attr_num($attr))
      {
	  carp("Unknown RADIUS tuple $attr\n")
	      if ($self->{unknown_entries});
	  next;
      }
      
      next unless ref($packer{$self->{Dict}->attr_type($attr)}) eq 'CODE';

      my $val = &{$packer{$self->{Dict}
			  ->attr_type($attr)}}
      ($self->attr($attr),
       $self->{Dict} ->attr_num($attr));

      $attstr .= pack $p_attr, $self->{Dict}->attr_num($attr),
      length($val)+2, $val;
  }

  # Pack the Vendor-Specific Attributes

  foreach my $vendor ($self->vendors) {
    foreach my $attr ($self->vsattributes($vendor)) {
      next unless ref($vsapacker{$self->{Dict}->vsattr_type($vendor, $attr)}) 
            eq 'CODE';
      foreach my $datum (@{$self->vsattr($vendor, $attr)}) {
        my $vval = &{$vsapacker{$self->{'Dict'}
        			->vsattr_type($vendor, $attr)}}
        ($datum, $self->{'Dict'}->vsattr_num($vendor, $attr), $vendor);
        
        if ($vendor == 429) {

      		# XXX - As pointed out by Quan Choi,
      		# we need special code to handle the
      		# 3Com case

          $attstr .= pack $p_vsa_3com, 26, 
          length($vval) + 10, $vendor,
          $self->{'Dict'}->vsattr_num($vendor, $attr),
          $vval;
        } else {
          $attstr .= pack $p_vsa, 26, length($vval) + 8, $vendor,
          $self->{'Dict'}->vsattr_num($vendor, $attr),
          length($vval) + 2, $vval;
        }
      }
    }
  }

  # Prepend the header and return the complete binary packet
  return pack $p_hdr, $codes{$self->code}, $self->identifier,
  length($attstr) + $hdrlen, $self->authenticator,
  $attstr;
}

sub unpack {
  my ($self, $data) = @_;
  my $dict = $self->{Dict};
  my $p_hdr  = "C C n a16 a*";    # Pack template for header
  my $p_attr = "C C a*";          # Pack template for attribute
  my %rcodes = (1  => 'Access-Request',      2  => 'Access-Accept',
		3  => 'Access-Reject',       4  => 'Accounting-Request',
		5  => 'Accounting-Response', 11 => 'Access-Challenge',
		12 => 'Status-Server',       13 => 'Status-Client');

  # Decode the header
  my ($code, $id, $len, $auth, $attrdat) = unpack $p_hdr, $data;

  # Generate a skeleton data structure to be filled in
  $self->set_code($rcodes{$code});
  $self->set_identifier($id);
  $self->set_authenticator($auth);

  # Functions for the various data types
  my %unpacker = 
	(
	 "string" => sub {
	     return $_[0];
	 },
	 "octets" => sub {
	     return $_[0];
	 },
	 "integer" => sub {
	     return $dict->val_has_name($_[1]) ?
		 $dict->val_name($_[1], 
				 unpack("N", $_[0]))
		     : unpack("N", $_[0]);
	 },
	 "ipaddr" => sub {
	     return length($_[0]) == 4 ? inet_ntoa($_[0]) : $_[0];
	 },
	 "address" => sub {
	     return length($_[0]) == 4 ? inet_ntoa($_[0]) : $_[0];
	 },
	 "time" => sub {
	     return unpack "N", $_[0];
	 },
	 "date" => sub {
	     return unpack "N", $_[0];
	 });

  my %vsaunpacker = 
      ( 
	"octets" => sub {
	    return $_[0];
	},
	"string" => sub {
	    return $_[0];
	},
	"integer" => sub {
	    $dict->vsaval_has_name($_[2], $_[1]) 
		? $dict->vsaval_name($_[2], $_[1], unpack("N", $_[0]))
		    : unpack("N", $_[0]);
	},
	"ipaddr" => sub {
	    return length($_[0]) == 4 ? inet_ntoa($_[0]) : $_[0];
	},
	"address" => sub {
	    return length($_[0]) == 4 ? inet_ntoa($_[0]) : $_[0];
	},
	"time" => sub {
	    return unpack "N", $_[0];
	},
	"date" => sub {
	    return unpack "N", $_[0];
	});
  
  
  # Unpack the attributes
  while (length($attrdat)) {
    my $length = unpack "x C", $attrdat;
    my ($type, $value) = unpack "C x a${\($length-2)}", $attrdat;
    if ($type == $VSA) {    # Vendor-Specific Attribute
      my ($vid, $vtype, $vlength) = unpack "N C C", $value;

      # XXX - How do we calculate the length
      # of the VSA? It's not defined!

      # XXX - 3COM seems to do things a bit differently. 
      # The IF below takes care of that. This was contributed by 
      # Ian Smith. Check the file CHANGES on this distribution for 
      # more information.

      my $vvalue;
      if ($vid == 429) {
        ($vid, $vtype) = unpack "N N", $value;
        $vvalue = unpack "xxxx xxxx a${\($length-10)}", $value;
      } else {
        $vvalue = unpack "xxxx x x a${\($vlength-2)}", $value;
      }

      if ((not defined $dict->vsattr_numtype($vid, $vtype)) or 
          (ref $vsaunpacker{$dict->vsattr_numtype($vid, $vtype)} ne 'CODE')) {
        my $whicherr = (defined $dict->vsattr_numtype($vid, $vtype)) ?
            "Garbled":"Unknown";
        warn "$whicherr vendor attribute $vid/$vtype for unpack()\n"
          unless $unkvprinted{"$vid/$vtype"};
        $unkvprinted{"$vid/$vtype"} = 1;
        substr($attrdat, 0, $length) = ""; # Skip this section
        next;
      }
      my $val = 
          &{$vsaunpacker{$dict->vsattr_numtype($vid, $vtype)}}($vvalue, 
                                   $vtype,
                                   $vid);
      $self->set_vsattr($vid, 
                $dict->vsattr_name($vid, $vtype), 
                $val);
    } else {            # Normal attribute
      if ((not defined $dict->attr_numtype($type)) or
          (ref ($unpacker{$dict->attr_numtype($type)}) ne 'CODE')) {
        my $whicherr = (defined $dict->attr_numtype($type)) ?
            "Garbled":"Unknown";
        warn "$whicherr general attribute $type for unpack()\n"
          unless $unkgprinted{$type};
        $unkgprinted{$type} = 1;
        substr($attrdat, 0, $length) = ""; # Skip this section
	next;
      }
      my $val = &{$unpacker{$dict->attr_numtype($type)}}($value, $type);
      $self->set_attr($dict->attr_name($type), $val);
    }
    substr($attrdat, 0, $length) = ""; # Skip this section
  }
}

1;
__END__

=head1 NAME

Net::Radius::Packet - Object-oriented Perl interface to RADIUS packets

=head1 SYNOPSIS

  use Net::Radius::Packet;
  use Net::Radius::Dictionary;

  my $d = new Net::Radius::Dictionary "/etc/radius/dictionary";

  my $p = new Net::Radius::Packet $d, $data;
  $p->dump;

  if ($p->attr('User-Name' eq "lwall") {
    my $resp = new Net::Radius::Packet $d;
    $resp->set_code('Access-Accept');
    $resp->set_identifier($p->identifier);
    $resp->set_authenticator($p->authenticator);
    $resp->set_attr('Reply-Message' => "Welcome, Larry!\r\n");
    my $respdat = auth_resp($resp->pack, "mysecret");
    ...

=head1 DESCRIPTION

RADIUS (RFC2138) specifies a binary packet format which contains
various values and attributes.  Net::Radius::Packet provides an
interface to turn RADIUS packets into Perl data structures and
vice-versa.

Net::Radius::Packet does not provide functions for obtaining RADIUS packets
from the network.  A simple network RADIUS server is provided as an
example at the end of this document.  

=head2 PACKAGE METHODS

=over 4

=item B<new Net::Radius::Packet $dictionary, $data>

Returns a new Net::Radius::Packet object. C<$dictionary> is an
optional reference to a Net::Radius::Dictionary object.  If not
supplied, you must call B<set_dict>.

If C<$data> is supplied, B<unpack> will be called for you to
initialize the object.

=back

=head2 OBJECT METHODS

There are actually two families of object methods. The ones described
below deal with standard RADIUS attributes. An additional set of methods
handle the Vendor-Specific attributes as defined in the RADIUS protocol.
Those methods behave in much the same way as the ones below with the
exception that the prefix B<vs> must be applied before the B<attr> in most
of the names. The vendor code must also be included as the first parameter
of the call.

The B<vsattr> and B<set_vsattr> methods, used to query and set
Vendor-Specific attributes return an array reference with the values
of each instance of the particular attribute in the packet. This
difference is required to support multiple VSAs with different
parameters in the same packet.

=over 4

=item B<-E<gt>set_dict($dictionary)>

Net::Radius::Packet needs access to a Net::Radius::Dictionary object to do
packing and unpacking.  set_dict must be called with an appropriate
dictionary reference (see L<Net::Radius::Dictionary>) before you can
use ->B<pack> or ->B<unpack>.

=item B<-E<gt>unpack($data)>

Given a raw RADIUS packet $data, unpacks its contents so that they
can be retrieved with the other methods (B<code>, B<attr>, etc.).

=item B<-E<gt>pack>

Returns a raw RADIUS packet suitable for sending to a RADIUS client
or server.

=item B<-E<gt>code>

Returns the Code field as a string.  As of this writing, the following
codes are defined:

        Access-Request          Access-Accept
        Access-Reject           Accounting-Request
        Accounting-Response     Access-Challenge
        Status-Server           Status-Client

=item B<-E<gt>set_code($code)>

Sets the Code field to the string supplied.

=item B<-E<gt>identifier()>

Returns the one-byte Identifier used to match requests with responses,
as a character value.

=item B<-E<gt>set_identifier($id)>

Sets the Identifier byte to the character supplied.

=item B<-E<gt>authenticator()>

Returns the 16-byte Authenticator field as a character string.

=item B<-E<gt>set_authenticator($authenticator)>

Sets the Authenticator field to the character string supplied.

=item B<-E<gt>attr($name)>

Retrieves the value of the named Attribute.  Attributes will
be converted automatically based on their dictionary type:

        STRING     Returned as a string.
        INTEGER    Returned as a Perl integer.
        IPADDR     Returned as a string (a.b.c.d)
        TIME       Returned as an integer

=item B<-E<gt>set_attr($name, $val)>

Sets the named Attribute to the given value.  Values should be supplied
as they would be returned from the B<attr> method.

=item B<-E<gt>unset_attr($name)>

Sets the named Attribute to the given value.  Values should be supplied
as they would be returned from the B<attr> method.

=item B<-E<gt>password($secret)>

The RADIUS User-Password attribute is encoded with a shared secret.
Use this method to return the decoded version. This also works when
the attribute name is 'Password' for compatibility reasons.

=item B<-E<gt>set_password($passwd, $secret)>

The RADIUS User-Password attribute is encoded with a shared secret.
Use this method to prepare the encoded version. Note that this method
always stores the encrypted password in the 'User-Password'
attribute. Some servers have been reported on insisting on this
attribute to be 'Password' instead.

=item B<-E<gt>dump()>

Prints the content of the packet to STDOUT.

=item B<-E<gt>show_unknown_entries($bool)>

Controls the generation of a C<warn()> whenever an unknown tuple is seen.

=back

=head2 EXPORTED SUBROUTINES

=over 4

=item B<auth_resp($packed_packet, $secret)>

Given a (packed) RADIUS packet and a shared secret, returns a new
packet with the Authenticator field changed in accordace with RADIUS
protocol requirements.

=back

=head1 NOTES

This document is (not yet) intended to be a complete description of
how to implement a RADIUS server. Please see the RFCs for that.  The
following is a brief description of the procedure:

  1. Receive a RADIUS request from the network.
  2. Unpack it using this package.
  3. Examine the attributes to determine the appropriate response.
  4. Construct a response packet using this package.
     Copy the Identifier and Authenticator fields from the request,
     set the Code as appropriate, and fill in whatever Attributes
     you wish to convey in to the server.
  5. Call the pack method and use the auth_resp function to
     authenticate it with your shared secret.
  6. Send the response back over the network.
  7. Lather, rinse, repeat.

=head1 EXAMPLE

    #!/usr/local/bin/perl -w

    use Net::Radius::Dictionary;
    use Net::Radius::Packet;
    use Net::Inet;
    use Net::UDP;
    use Fcntl;
    use strict;

    # This is a VERY simple RADIUS authentication server which responds
    # to Access-Request packets with Access-Accept.  This allows anyone
    # to log in.

    my $secret = "mysecret";  # Shared secret on the term server

    # Parse the RADIUS dictionary file (must have dictionary in current dir)
    my $dict = new Net::Radius::Dictionary "dictionary"
      or die "Couldn't read dictionary: $!";

    # Set up the network socket (must have radius in /etc/services)
    my $s = new Net::UDP { thisservice => "radius" } or die $!;
    $s->bind or die "Couldn't bind: $!";
    $s->fcntl(F_SETFL, $s->fcntl(F_GETFL,0) | O_NONBLOCK)
      or die "Couldn't make socket non-blocking: $!";

    # Loop forever, recieving packets and replying to them
    while (1) {
      my ($rec, $whence);
      # Wait for a packet
      my $nfound = $s->select(1, 0, 1, undef);
      if ($nfound > 0) {
	# Get the data
	$rec = $s->recv(undef, undef, $whence);
	# Unpack it
	my $p = new Net::Radius::Packet $dict, $rec;
	if ($p->code eq 'Access-Request') {
	  # Print some details about the incoming request (try ->dump here)
	  print $p->attr('User-Name'), " logging in with password ",
		$p->password($secret), "\n";
	  # Create a response packet
	  my $rp = new Net::Radius::Packet $dict;
	  $rp->set_code('Access-Accept');
	  $rp->set_identifier($p->identifier);
	  $rp->set_authenticator($p->authenticator);
	  # (No attributes are needed.. but you could set IP addr, etc. here)
	  # Authenticate with the secret and send to the server.
	  $s->sendto(auth_resp($rp->pack, $secret), $whence);
	}
	else {
	  # It's not an Access-Request
	  print "Unexpected packet type recieved.";
	  $p->dump;
	}
      }
    }

=head1 AUTHOR

Christopher Masto, <chris@netmonger.net>. VSA support by Luis
E. Muñoz, <luismunoz@cpan.org>. Fix for unpacking 3COM VSAs
contributed by Ian Smith <iansmith@ncinter.net>. Information for
packing of 3Com VSAs provided by Quan Choi <Quan_Choi@3com.com>. Some
functions contributed by Tony Mountifield <tony@mountifield.org>.


=head1 SEE ALSO

Net::Radius::Dictionary

=cut
