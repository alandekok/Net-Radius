use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Net::Radius',
    'VERSION_FROM' => 'version.pl', # finds $VERSION
    'PM' => {
	     map { ("$_.pm" => "\$(INST_LIBDIR)/$_.pm") }
	         qw(Radius/Packet Radius/Dictionary)
	    },
    'dist' => {COMPRESS => 'gzip -9f', SUFFIX => 'gz'}
);
