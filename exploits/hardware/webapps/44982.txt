SEC Consult Vulnerability Lab Security Advisory < 20180704-1 >
=======================================================================
title: Authorization Bypass
product: All ADB Broadband Gateways / Routers
(based on Epicentro platform)
vulnerable version: Hardware: ADB P.RG AV4202N, DV2210, VV2220, VV5522, etc.
fixed version: see "Solution" section below
CVE number: CVE-2018-13109
impact: critical
homepage: http://www.adbglobal.com
found: 2016-06-28
by: Johannes Greil (Office Vienna)
SEC Consult Vulnerability Lab

An integrated part of SEC Consult
Europe | Asia | North America

https://www.sec-consult.com
=======================================================================

Vendor description:
-------------------
"ADB creates and delivers the right solutions that enable our customers to
reduce integration and service delivery challenges to increase ARPU and reduce
churn. We combine ADB know-how and products with those from a number of third
party industry leaders to deliver complete solutions that benefit from
collaborative thinking and best in class technologies."

Source: https://www.adbglobal.com/about-adb/

"Founded in 1995, ADB initially focused on developing and marketing software
for digital TV processors and expanded its business to the design and
manufacture of digital TV equipment in 1997. The company sold its first set-top
box in 1997 and since then has been delivering a number of set-top boxes, and
Gateway devices, together with advanced software platforms. ADB has sold over
60 million devices worldwide to cable, satellite, IPTV and broadband operators.
ADB employs over 500 people, of which 70% are in engineering functions."

Source: https://en.wikipedia.org/wiki/Advanced_Digital_Broadcast

Business recommendation:
------------------------
By exploiting the authorization bypass vulnerability on affected and unpatched
devices an attacker is able to gain access to settings that are otherwise
forbidden for the user, e.g. through strict settings set by the ISP. It is also
possible to manipulate settings to e.g. enable the telnet server for remote
access if it had been previously disabled by the ISP. The attacker needs some
user account, regardless of the permissions, for login, e.g. the default one
provided by the ISP or printed on the device can be used.

It is highly recommended by SEC Consult to perform a thorough security review
by security professionals for this platform. It is assumed that further critical
vulnerabilities exist within the firmware of this device.

Vulnerability overview/description:
-----------------------------------
1) Authorization bypass vulnerability (CVE-2018-13109)
Depending on the firmware version/feature-set of the ISP deploying the ADB
device, a standard user account may not have all settings enabled within
the web GUI.

An authenticated attacker is able to bypass those restrictions by adding a
second slash in front of the forbidden entry of the path in the URL.
It is possible to access forbidden entries within the first layer of the web
GUI, any further subsequent layers/paths (sub menus) were not possible to access
during testing but further exploitation can't be ruled out entirely.

Proof of concept:
-----------------
1) Authorization bypass vulnerability (CVE-2018-13109)
Assume the following URL is blocked/forbidden within the web GUI settings:
http://$IP/ui/dboard/settings/management/telnetserver

Adding a second slash in front of the blocked entry "telnetserver" will enable
full access including write permissions to change settings:
http://$IP/ui/dboard/settings/management//telnetserver

This works for many other settings within the web GUI!

In our tests it was not possible to access subsequent layers, e.g.:
Assume that both the proxy menu and submenu "rtsp" settings are blocked,
a second slash will _not_ enable access to the RTSP settings:
http://$IP/ui/dboard/settings/proxy//rtsp

Nevertheless, it can't be ruled out that sub menus can be accessed too when
further deeper tests are being performed.

Vulnerable / tested versions:
-----------------------------
The following devices & firmware have been tested which were the most recent
versions at the time of discovery:

The firmware versions depend on the ISP / customer of ADB and may vary!

ADB P.RG AV4202N - E_3.3.0, latest firmware version, depending on ISP
ADB DV 2210 - E_5.3.0, latest firmware version, depending on ISP
ADB VV 5522 - E_8.3.0, latest firmware version, depending on ISP
ADB VV 2220 - E_9.0.6, latest firmware version, depending on ISP
etc.

It has been confirmed by ADB that _all_ their ADB modems / gateways / routers
based on the Epicentro platform are affected by this vulnerability in all
firmware versions for all their customers (ISPs) at the time of identification
of the vulnerability _except_ those devices which have a custom UI developed
for the ISP.

Vendor contact timeline:
------------------------
2016-07-01: Contacting vendor ADB, sending encrypted advisory, asking about
affected devices
2016-07-08: Receiving information about affected devices
2016-07 - 2017-04: Further coordination, waiting for firmware release,
implementation & rollout phases for their customers
2018-07-04: Embargo lifted, public release of security advisory

Solution:
---------
The firmware versions depend on the ISP / customer of ADB and may vary!

Patch version:

ADB P.RG AV4202N >= E_3.3.2, firmware version depending on ISP
ADB DV2210 >= E_5.3.2, firmware version depending on ISP
ADB VV5522 >= E_8.3.2, firmware version depending on ISP
ADB VV2220 >= E_9.3.2, firmware version depending on ISP
etc.

Workaround:
-----------
Restrict access to the web interface and only allow trusted users.
Change any default/weak passwords to strong credentials.
Don't allow remote access to the web GUI via Internet.

Advisory URL:
-------------
https://www.sec-consult.com/en/vulnerability-lab/advisories/index.html

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SEC Consult Vulnerability Lab

SEC Consult
Europe | Asia | North America

About SEC Consult Vulnerability Lab
The SEC Consult Vulnerability Lab is an integrated part of SEC Consult. It
ensures the continued knowledge gain of SEC Consult in the field of network
and application security to stay ahead of the attacker. The SEC Consult
Vulnerability Lab supports high-quality penetration testing and the evaluation
of new offensive and defensive technologies for our customers. Hence our
customers obtain the most current information about vulnerabilities and valid
recommendation about the risk profile of new technologies.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Interested to work with the experts of SEC Consult?
Send us your application https://www.sec-consult.com/en/career/index.html

Interested in improving your cyber security with the experts of SEC Consult?
Contact our local offices https://www.sec-consult.com/en/contact/index.html
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Mail: research at sec-consult dot com
Web: https://www.sec-consult.com
Blog: http://blog.sec-consult.com
Twitter: https://twitter.com/sec_consult

EOF J. Greil / @2018