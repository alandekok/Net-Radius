package Net::Radius::Dictionary;

use strict;
use warnings;
use vars qw($VERSION);

# $Id: Dictionary.pm,v 1.6 2006/08/09 16:00:01 lem Exp $

$VERSION = '1.45';

sub new {
  my $class = shift;
  my $self = { 
      rvsattr	=> {},
      vsattr	=> {},
      vsaval	=> {},
      rvsaval	=> {},
      attr	=> {},
      rattr	=> {},
      val	=> {},
      rval	=> {},
      vendors	=> {},
  };
  bless $self, $class;
  $self->readfile($_[0]) if defined($_[0]);
  return $self;
}

sub readfile {
  my ($self, $filename) = @_;

  open DICT, "<$filename";

  while (defined(my $l = <DICT>)) {
    next if $l =~ /^\#/;
    next unless my @l = split /\s+/, $l;

    if ($l[0] =~ m/^vendor$/i) 
    {
	if (defined $l[1] and defined $l[2] and $l[2] =~ /^[xo0-9]+$/)
	{
	    if (substr($l[2],0,1) eq "0") { #allow hex or octal
		my $num = lc($l[2]);
		$num =~ s/^0b//;
		$l[2] = oct($num);
	    }   
	    $self->{vendors}->{$l[1]} = $l[2];
	}
	else
	{
	    warn "Garbled VENDOR line $l\n";
	}
    }
    elsif ($l[0] =~ m/^attribute$/i) 
    {
	if (@l == 4)
	{
	    $self->{attr}->{$l[1]}  = [@l[2,3]];
	    $self->{rattr}->{$l[2]} = [@l[1,3]];
	}
	elsif (@l == 5)		# VENDORATTR
	{
	    if (substr($l[2],0,1) eq "0") { #allow hex or octal
		my $num = lc($l[2]);
		$num =~ s/^0b//;
		$l[2] = oct($num);
	    }   
	    if (exists $self->{vendors}->{$l[4]})
	    {
		$self->{vsattr}->{$self->{vendors}->{$l[4]}}->{$l[1]} 
		= [@l[2, 3]];
		$self->{rvsattr}->{$self->{vendors}->{$l[4]}}->{$l[2]} 
		= [@l[1, 3]];
	    }
	    else
	    {
		warn "Warning: Unknown vendor $l[4]\n";
	    }
	}
    }
    elsif ($l[0] =~ m/^value$/i) {
      if (exists $self->{attr}->{$l[1]}) {
	  $self->{val}->{$self->{attr}->{$l[1]}->[0]}->{$l[2]}  = $l[3];
	  $self->{rval}->{$self->{attr}->{$l[1]}->[0]}->{$l[3]} = $l[2];
      }
      else {
	  for my $v (keys %{$self->{vsattr}})
	  {
	      if (defined $self->{vsattr}->{$v}->{$l[1]})
	      {
		  $self->{vsaval}->{$v}->{$self->{vsattr}->{$v}
					      ->{$l[1]}->[0]}->{$l[2]} 
		  = $l[3];
		  $self->{rvsaval}->{$v}->{$self->{vsattr}->{$v}
					   ->{$l[1]}->[0]}->{$l[3]} 
		  = $l[2];
	      }
	  }
      }
    }
    elsif ($l[0] =~ m/^vendorattr$/i) {
	if (substr($l[3],0,1) eq "0") { #allow hex or octal
          my $num = lc($l[3]);
          $num =~ s/^0b//;
          $l[3] = oct($num);
	}   
	$self->{vsattr}->{$l[1]}->{$l[2]} = [@l[3, 4]];
	$self->{rvsattr}->{$l[1]}->{$l[3]} = [@l[2, 4]];
    }
    elsif ($l[0] =~ m/^vendorvalue$/i) {
	if (substr($l[4],0,1) eq "0") 
	{ #allow hex or octal 
          my $num = lc($l[4]);
          $num =~ s/^0b//;
          $l[4] = oct($num);
	}
	if (defined $self->{vsattr}->{$l[1]}->{$l[2]}) {
	    $self->{vsaval}->{$l[1]}->{$self->{vsattr}->{$l[1]}->{$l[2]}
				       ->[0]}->{$l[3]} = $l[4];
	    $self->{rvsaval}->{$l[1]}->{$self->{vsattr}->{$l[1]}->{$l[2]}
					->[0]}->{$l[4]} = $l[3];
	}
	else {
	    warn "Warning: $filename contains vendor value for ",
	    "unknown vendor attribute - ignored",
	    "\"$l[1]\"\n  $l";
	}
    }
    else {
      warn "Warning: Weird dictionary line: $l\n";
    }
  }
  close DICT;
}

# Accessors for standard attributes

sub vendor_num	 { $_[0]->{vendors}->{$_[1]};		}
sub attr_num     { $_[0]->{attr}->{$_[1]}->[0];		}
sub attr_type    { $_[0]->{attr}->{$_[1]}->[1];		}
sub attr_name    { $_[0]->{rattr}->{$_[1]}->[0];	}
sub attr_numtype { $_[0]->{rattr}->{$_[1]}->[1];	}
sub attr_has_val { $_[0]->{val}->{$_[1]};		}
sub val_has_name { $_[0]->{rval}->{$_[1]};		}
sub val_num      { $_[0]->{val}->{$_[1]}->{$_[2]};	}
sub val_name     { $_[0]->{rval}->{$_[1]}->{$_[2]};	}

# Accessors for Vendor-Specific Attributes

sub vsattr_num      { $_[0]->{vsattr}->{$_[1]}->{$_[2]}->[0];		}
sub vsattr_type     { $_[0]->{vsattr}->{$_[1]}->{$_[2]}->[1];		}
sub vsattr_name     { $_[0]->{rvsattr}->{$_[1]}->{$_[2]}->[0];		}
sub vsattr_numtype  { $_[0]->{rvsattr}->{$_[1]}->{$_[2]}->[1];		}
sub vsattr_has_val  { $_[0]->{vsaval}->{$_[1]}->{$_[2]};		}
sub vsaval_has_name { $_[0]->{rvsaval}->{$_[1]}->{$_[2]};		}
sub vsaval_num      { $_[0]->{vsaval}->{$_[1]}->{$_[2]}->{$_[3]};	}
sub vsaval_name     { $_[0]->{rvsaval}->{$_[1]}->{$_[2]}->{$_[3]};	}

1;
__END__

=head1 NAME

Net::Radius::Dictionary - RADIUS dictionary parser

=head1 SYNOPSIS

  use Net::Radius::Dictionary;

  my $dict = new Net::Radius::Dictionary "/etc/radius/dictionary";
  $dict->readfile("/some/other/file");
  my $num = $dict->attr_num('User-Name');
  my $name = $dict->attr_name(1);
  my $vsa_num = $dict->vsattr_num(9, 'cisco-avpair');
  my $vsa_name = $dict->vsattr_name(9, 1);

=head1 DESCRIPTION

This is a simple module that reads a RADIUS dictionary file and
parses it, allowing conversion between dictionary names and numbers.
Vendor-Specific attributes are supported in a way consistent to the
standards.

A few earlier versions of this module attempted to make dictionaries
case-insensitive. This proved to be a very bad decision. From this
version on, this tendency is reverted: Dictionaries and its contents
are to be case-sensitive to prevent random, hard to debug failures in
production code.

=head2 METHODS

=over

=item B<new($dict_file)>

Returns a new instance of a Net::Radius::Dictionary object. This
object will have no attributes defined, as expected.

If given an (optional) filename, it calls I<readfile> for you.

=item B<-E<gt>readfile($dict_file)>

Parses a dictionary file and learns the mappings to use. It can be
called multiple times for the same object. The result will be that new
entries will override older ones, thus you could load a default
dictionary and then have a smaller dictionary that override specific
entries.

=item B<-E<gt>vendor_num($vendorname)>

Return the vendor number for the given vendor name.

=item B<-E<gt>attr_num($attrname)>

Returns the number of the named attribute.

=item B<-E<gt>attr_type($attrname)>

Returns the type (I<string>, I<integer>, I<ipaddr>, or I<time>) of the
named attribute.

=item B<-E<gt>attr_name($attrnum)>

Returns the name of the attribute with the given number.

=item B<-E<gt>attr_numtype($attrnum)>

Returns the type of the attribute with the given number.

=item B<-E<gt>attr_has_val($attrnum)>

Returns a true or false value, depending on whether or not the numbered
attribute has any known value constants.

=item B<-E<gt>val_has_name($attrnum)>

Alternate (bad) name for I<attr_has_val>.

=item B<-E<gt>val_num($attrnum, $valname)>

Returns the number of the named value for the attribute number supplied.

=item B<-E<gt>val_name($attrnum, $valnumber)>

Returns the name of the numbered value for the attribute number supplied.

=back

There is an equivalent family of accessor methods for Vendor-Specific
attributes and its values. Those methods are identical to their standard
attributes counterparts with two exceptions. Their names have a
I<vsa> prepended to the accessor name and the first argument to each one
is the vendor code on which they apply.

=head1 CAVEATS

This module is mostly for the internal use of Net::Radius::Packet, and
may otherwise cause insanity and/or blindness if studied.

=head1 AUTHOR

Christopher Masto <chris@netmonger.net>, 
Luis E. Muñoz <luismunoz@cpan.org> contributed the VSA code.

=head1 SEE ALSO

Net::Radius::Packet

=cut
