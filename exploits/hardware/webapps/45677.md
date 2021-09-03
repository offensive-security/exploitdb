## Password stored in plaintext
CVE: CVE-2018-10824

Description:

An issue was discovered on D-Link routers:

DWR-116 through 1.06,
DIR-140L through 1.02,
DIR-640L through 1.02,
DWR-512 through 2.02,
DWR-712 through 2.02,
DWR-912 through 2.02,
DWR-921 through 2.02,
DWR-111 through 1.01,
and probably others with the same type of firmware.
NOTE: I have changed the filename in description to XXX because the vendor leaves some EOL routers unpatched and the attack is too simple

The administrative password is stored in plaintext in the /tmp/XXX/0 file. An attacker having a directory traversal (or LFI) can easily get full router access.

PoC using the directory traversal vulnerability disclosed above - CVE-2018-10822

`$ curl http://routerip/uir//tmp/XXX/0`
This command returns a binary config file which contains admin username and password as well as many other router configuration settings. By using the directory traversal vulnerability it is possible to read the file without authentication.