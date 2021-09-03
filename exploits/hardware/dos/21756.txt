source: https://www.securityfocus.com/bid/5571/info

A denial of service vulnerability has been reported in the Belkin F5D6130 Wireless Network Access Point.

Reportedly, this issue may be exploited by making a sequence of SNMP requests. A valid community name is not required. After a number of SNMP requests are made, the device will fail to respond to further requests. Additionally, all wireless connections will be dropped, and new connections refused.

Under some conditions, the device may also fail to respond on the ethernet interface.

snmpwalk <ip address> <arbitrary objectID>