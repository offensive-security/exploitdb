######################################################################################
# Exploit Title: D-Link DIR-615 Wireless Router - Persistent Cross Site Scripting (XSS)
# Date: 14.04.2018
# Exploit Author: Sayan Chatterjee
# Vendor Homepage: http://www.dlink.co.in
# Hardware Link: http://www.dlink.co.in/products/?pid=678
# Category: Hardware (Wi-fi Router)
# Hardware Version: T1
# Firmware Version: 20.07
# Tested on: Windows 10
# CVE: CVE-2018-10110
#######################################################################################

Reproduction Steps:
------------------------------
1. Go to your wi-fi router gateway [i.e: http://192.168.0.1]
2. Go to –> “Maintenance” –> “Admin”
3. Create a user with name alert_"HI"
4. Refresh the page and you will be having “HI” popup

#######################################################################################