source: https://www.securityfocus.com/bid/1009/info

A vulnerability exists in the Nortel/Bay Networks Nautica Marlin router pruduct. Sending a 0 byte UDP packet to port 161 (SNMP) to one of these routers will cause it to crash. This attack can be trivially performed using NMAP or other UDP port scanner.

nmap -sU -p 161 hosttodos