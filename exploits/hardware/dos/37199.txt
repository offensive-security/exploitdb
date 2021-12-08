# Exploit Title: ZTE AC 3633R USB Modem Multiple Vulnerabilities
# Date: 4/06/2015
# Exploit Author: [Vishnu (@dH3wK)
# Vendor Homepage: [http://zte.com.cn
# Version: 3633R
# Tested on: Windows, Linux


Greetings from vishnu (@dH4wk)

1. Vulnerable Product Version

- ZTE AC3633R (MTS Ultra Wifi Modem)

2. Vulnerability Information

(A) Authentication Bypass
Impact: Attacker gains administrative access
Remotely Exploitable: UNKNOWN
Locally Exploitable: YES

(B) Device crash which results in reboot
Impact: Denial of service, The crash may lead to RCE locally thus
attaining root privilege on the device
Remotely Exploitable: UNKNOWN
Locally Exploitable: YES

3. Vulnerability Description

(A) The administrative authentication mechanism of the modem can be
bypassed by feeding with a string of 121 characters in length, either in
username or password field.

(B) A crash causes the modem to restart. This is caused when either of
the password or username fields are fed with an input of 130 characters
or above.

[Note: If username is targeted for exploitation, then password field shall
be fed with minimum 6 characters (any characters) and vice versa ]