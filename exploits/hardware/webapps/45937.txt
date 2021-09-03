# Exploit Title: Rockwell Automation Allen-Bradley PowerMonitor 1000 - Incorrect Access Control
# Date: 2018-11-27
# Exploit Author: Luca.Chiou
# Vendor Homepage: https://www.rockwellautomation.com/
# Version: 1408-EM3A-ENT B
# Tested on: It is a proprietary devices: https://ab.rockwellautomation.com/zh/Energy-Monitoring/1408-PowerMonitor-1000
# CVE : CVE-2018-19616

# 1. Description:
# In Rockwell Automation Allen-Bradley PowerMonitor 1000 web page, there are a few buttons are disabled,
# such as “Edit”, “Remove”, “AddNew”, “Change Policy Holder” and “Security Configuration”.
# View the source code of login page, those buttons/functions just use the “disabled” parameter to control the access right.
# It is allow attackers using proxy to erase the “disabled” parameter, and enable those buttons/functions.
# Once those buttons/functions are enabled.
# Attackers is capable to add a new user who have administrator right.