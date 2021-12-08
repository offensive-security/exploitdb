Trustwave SpiderLabs Security Advisory TWSL2013-021:
Multiple Vulnerabilities in Karotz Smart Rabbit

Published: 08/01/13
Version: 1.0

Vendor: Electronic Arts (http://www.ea.com/), formerly Mindscape, formerly Violet
Product: Karotz
Version affected:  12.07.19.00

Product description:
Karotz is the successor to the "Nabaztag". Nabaztag is a Wi-Fi enabled
ambient electronic device in the shape of a rabbit, invented by Rafi
Haladjian and Olivier Mével, and manufactured by the company Violet.[1]
Nabaztag was designed to be a "smart object" comparable to those
manufactured by Ambient Devices; it can connect to the Internet (to
download weather forecasts, read its owner's email, etc.). It is also
customizable and programmable to an extent.

Finding 1: Python Module Hijacking
*****Credit: Daniel Crowley of Trustwave SpiderLabs
CVE: CVE-2013-4867
CWE: CWE-427

During the setup process for a Karotz unit, if wifi is selected as the
method used to connect to the Internet, a python script named "autorunwifi"
is run as root to set up the wifi connectivity. This file, along with
several others, is placed in the root of a USB flash drive or hard drive.
Another file, named "autorunwifi.sig", contains a signature of autorunwifi
signed with the private key for Violet, to prevent modifications to the
"autorunwifi" script.

Since Python first attempts to load modules not built into Python from the
same directory as the invoked script, it is possible to override the
functionality of imported modules by placing a file with the same basename
as the module being imported and an extension of ".py". In this case, it is
possible to write a Python script named "simplejson.py" and place it in the
same directory as the other setup files, which will cause the contents of
simplejson.py to be executed at the beginning of the "autorunwifi" script
execution.

This attack requires a USB flash drive to be plugged into the Karotz unit,
and requires the Karotz to be turned off and on.

The following is a proof of concept "simplejson.py" file that will copy the
pubring.gpg file from the Karotz onto the inserted USB key, which is
processed with MD5 to produce the key used to decrypt the root filesystem
for the Karotz:

## simplejson.py
import os

os.system("cp /karotz/etc/gpg/pubring.gpg /mnt/usbkey")
## end simplejson.py

Finding 2: API Session Token Passed in Cleartext
*****Credit: Daniel Crowley of Trustwave SpiderLabs
CVE: CVE-2013-4868

There are two kinds of applications for the Karotz: hosted and external.
Hosted applications are stored and run on the Karotz itself. External
applications run outside the Karotz unit and control the Karotz through an
api at api.karotz.com. Both types of applications must specifically request
to use parts of the karotz in the manifest file of their application
package. For instance, if your application uses the webcam and ears, you
must specify in your application manifest that these will be used by your
application before they will be available to your application.

The control is performed over plaintext HTTP. As such, the session token
authenticating API calls used to control the Karotz is available to an
eavesdropping attacker. The session token can be used to perform any remote
API call available to the application. For instance, if the application
uses the webcam, a video could be captured using the webcam and sent to an
arbitrary server.


Vendor Response:
No response received.

Remediation Steps:
No official patch is available.  To limit exposure,
network access to these devices should be limited to authorized
personnel through the use of Access Control Lists and proper
network segmentation.

Revision History:
06/19/13 - Attempt to contact vendor
07/10/13 - Attempt to contact vendor
07/12/13 - Attempt to contact vendor
08/01/13 - Advisory published

Additional Credits:
Discussion of Python module loading behavior and initial suggestion of
application to Karotz by Jennifer Savage

References
1. http://www.karotz.com
2. http://savagejen.github.io/blog/2013/04/28/python-module-hijacking/


About Trustwave:
Trustwave is the leading provider of on-demand and subscription-based
information security and payment card industry compliance management
solutions to businesses and government entities throughout the world. For
organizations faced with today's challenging data security and compliance
environment, Trustwave provides a unique approach with comprehensive
solutions that include its flagship TrustKeeper compliance management
software and other proprietary security solutions. Trustwave has helped
thousands of organizations--ranging from Fortune 500 businesses and large
financial institutions to small and medium-sized retailers--manage
compliance and secure their network infrastructure, data communications and
critical information assets. Trustwave is headquartered in Chicago with
offices throughout North America, South America, Europe, Africa, China and
Australia. For more information, visit https://www.trustwave.com

About Trustwave SpiderLabs:
SpiderLabs(R) is the advanced security team at Trustwave focused on
application security, incident response, penetration testing, physical
security and security research. The team has performed over a thousand
incident investigations, thousands of penetration tests and hundreds of
application security tests globally. In addition, the SpiderLabs Research
team provides intelligence through bleeding-edge research and proof of
concept tool development to enhance Trustwave's products and services.
https://www.trustwave.com/spiderlabs

Disclaimer:
The information provided in this advisory is provided "as is" without
warranty of any kind. Trustwave disclaims all warranties, either express or
implied, including the warranties of merchantability and fitness for a
particular purpose. In no event shall Trustwave or its suppliers be liable
for any damages whatsoever including direct, indirect, incidental,
consequential, loss of business profits or special damages, even if
Trustwave or its suppliers have been advised of the possibility of such
damages. Some states do not allow the exclusion or limitation of liability
for consequential or incidental damages so the foregoing limitation may not
apply.

________________________________

This transmission may contain information that is privileged, confidential, and/or exempt from disclosure under applicable law. If you are not the intended recipient, you are hereby notified that any disclosure, copying, distribution, or use of the information contained herein (including any reliance thereon) is STRICTLY PROHIBITED. If you received this transmission in error, please immediately contact the sender and destroy the material in its entirety, whether in electronic or hard copy format.