Directory Traversal
CVE: CVE-2018-10822

CVSS v3: 8.6
AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N

Description: Directory traversal vulnerability in the web interface on D-Link routers:

DWR-116 through 1.06,
DIR-140L through 1.02,
DIR-640L through 1.02,
DWR-512 through 2.02,
DWR-712 through 2.02,
DWR-912 through 2.02,
DWR-921 through 2.02,
DWR-111 through 1.01,
and probably others with the same type of firmware
allows remote attackers to read arbitrary files via a /.. or // after “GET /uir” in an HTTP request.

NOTE: this vulnerability exists because of an incorrect fix for CVE-2017-6190.

PoC:

`$ curl http://routerip/uir//etc/passwd`
The vulnerability can be used retrieve administrative password using the other disclosed vulnerability - CVE-2018-10824.

This vulnerability was reported previously by Patryk Bogdan in CVE-2017-6190 but he reported it is fixed in certain release but unfortunately it is still present in even newer releases. The vulnerability is also present in other D-Link routers and can be exploited not only (as the original author stated) by double dot but also absolutely using double slash.